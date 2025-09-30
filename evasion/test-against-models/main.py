import requests
import concurrent.futures
from collections import defaultdict
import matplotlib.pyplot as plt
import numpy as np
import os
from tqdm import tqdm


def get_verdict(file_path):
    """
    Performs a curl-like POST request and returns the result.

    Args:
        file_path (str): The full path to the file to be sent.

    Returns:
        tuple: A tuple containing the file path and the result (0 or 1),
               or None if the request fails.
    """
    try:
        # Check if file exists first
        if not os.path.exists(file_path):
            print(f"ERROR: File not found: {file_path}")
            return (file_path, None)

        with open(file_path, "rb") as f:
            data = f.read()

        headers = {"Content-Type": "application/octet-stream"}
        url = "http://127.0.0.1:8080"

        response = requests.post(url, data=data, headers=headers, timeout=30)
        response.raise_for_status()  # Raise an HTTPError for bad responses (4xx or 5xx)

        json_response = response.json()
        result = json_response.get("result")

        return (file_path, result)

    except FileNotFoundError:
        print(f"ERROR: File not found: {file_path}")
        return (file_path, None)
    except requests.exceptions.RequestException as e:
        print(f"ERROR: Request failed for {file_path}: {e}")
        return (file_path, None)
    except Exception as e:
        print(f"ERROR: Unexpected error for {file_path}: {e}")
        return (file_path, None)


def main():
    """
    Main function to orchestrate the multithreaded requests and analysis.
    Uses 4 threads for optimal performance with localhost API.
    """
    base_paths = [
        "/home/dakota/csce-439/evasion-samples/blackbox/crypt-only",
        "/home/dakota/csce-439/evasion-samples/blackbox/pipeline-crypt",
        "/home/dakota/csce-439/evasion-samples/blackbox/pipeline-packed",
    ]

    # Store results for each base path
    all_results = defaultdict(lambda: {"goodware": 0, "malware": 0, "errors": 0})

    # Process each directory sequentially to reduce memory usage
    for base_path in base_paths:
        print(f"Processing {os.path.basename(base_path)}...")

        # Generate a list of file paths (1-50)
        file_paths = [f"{base_path}/{i}" for i in range(1, 51)]

        # Verify files exist before processing
        existing_files = [f for f in file_paths if os.path.exists(f)]
        missing_files = [f for f in file_paths if not os.path.exists(f)]

        if missing_files:
            print(
                f"WARNING: {len(missing_files)} files not found in {os.path.basename(base_path)}"
            )
            print(
                f"Missing files: {missing_files[:5]}{'...' if len(missing_files) > 5 else ''}"
            )

        print(f"Found {len(existing_files)} files to process")

        # Use a ThreadPoolExecutor with 4 workers for optimal localhost API performance
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
            # Use executor.map to apply the function concurrently
            results_iterator = executor.map(get_verdict, file_paths)

            # Process results with a progress bar
            for file_path, result in tqdm(
                results_iterator,
                total=len(file_paths),
                desc=f"Processing {os.path.basename(base_path)}",
            ):
                if result is not None:
                    if result == 0:
                        all_results[base_path]["goodware"] += 1
                    elif result == 1:
                        all_results[base_path]["malware"] += 1
                else:
                    all_results[base_path]["errors"] += 1

    # Print the final summary
    print("\n" + "=" * 60)
    print("FINAL SUMMARY")
    print("=" * 60)
    for path, counts in all_results.items():
        total = counts["goodware"] + counts["malware"] + counts["errors"]
        print(f"\nResults for {os.path.basename(path)}:")
        print(
            f"  Goodware (result = 0): {counts['goodware']} ({counts['goodware']/total*100:.1f}%)"
        )
        print(
            f"  Malware (result = 1): {counts['malware']} ({counts['malware']/total*100:.1f}%)"
        )
        print(f"  Errors: {counts['errors']} ({counts['errors']/total*100:.1f}%)")
        print(f"  Total processed: {total}")
    print("=" * 60)

    # Create the visualization
    print("\nCreating visualizations...")
    plot_results(all_results)


def plot_results(results):
    """
    Creates multiple visualizations to analyze the goodware and malware counts.
    """

    labels = [os.path.basename(path) for path in results.keys()]
    goodware_counts = [data["goodware"] for data in results.values()]
    malware_counts = [data["malware"] for data in results.values()]
    error_counts = [data["errors"] for data in results.values()]

    # Create a figure with multiple subplots
    fig = plt.figure(figsize=(15, 10))

    # 1. Stacked Bar Chart
    ax1 = plt.subplot(2, 2, 1)
    x = range(len(labels))
    width = 0.6

    p1 = ax1.bar(
        x, goodware_counts, width, label="Goodware", color="forestgreen", alpha=0.8
    )
    p2 = ax1.bar(
        x,
        malware_counts,
        width,
        bottom=goodware_counts,
        label="Malware",
        color="firebrick",
        alpha=0.8,
    )
    p3 = ax1.bar(
        x,
        error_counts,
        width,
        bottom=np.array(goodware_counts) + np.array(malware_counts),
        label="Errors",
        color="orange",
        alpha=0.8,
    )

    ax1.set_ylabel("Count")
    ax1.set_title("Stacked Bar Chart: Verdicts by Category")
    ax1.set_xticks(x)
    ax1.set_xticklabels(labels, rotation=45, ha="right")
    ax1.legend()
    ax1.grid(True, alpha=0.3)

    # Add value labels on bars
    for i, (g, m, e) in enumerate(zip(goodware_counts, malware_counts, error_counts)):
        total = g + m + e
        if total > 0:
            ax1.text(
                i, total + 0.5, f"{total}", ha="center", va="bottom", fontweight="bold"
            )

    # 2. Side-by-side Bar Chart
    ax2 = plt.subplot(2, 2, 2)
    x_pos = np.arange(len(labels))
    width = 0.25

    rects1 = ax2.bar(
        x_pos - width,
        goodware_counts,
        width,
        label="Goodware",
        color="forestgreen",
        alpha=0.8,
    )
    rects2 = ax2.bar(
        x_pos, malware_counts, width, label="Malware", color="firebrick", alpha=0.8
    )
    rects3 = ax2.bar(
        x_pos + width, error_counts, width, label="Errors", color="orange", alpha=0.8
    )

    ax2.set_ylabel("Count")
    ax2.set_title("Side-by-Side Bar Chart: Verdicts by Category")
    ax2.set_xticks(x_pos)
    ax2.set_xticklabels(labels, rotation=45, ha="right")
    ax2.legend()
    ax2.grid(True, alpha=0.3)

    # 3. Pie Chart for Overall Distribution
    ax3 = plt.subplot(2, 2, 3)
    total_goodware = sum(goodware_counts)
    total_malware = sum(malware_counts)
    total_errors = sum(error_counts)

    sizes = [total_goodware, total_malware, total_errors]
    labels_pie = ["Goodware", "Malware", "Errors"]
    colors = ["forestgreen", "firebrick", "orange"]

    # Only show pie chart if there are results
    if sum(sizes) > 0:
        wedges, texts, autotexts = ax3.pie(
            sizes, labels=labels_pie, colors=colors, autopct="%1.1f%%", startangle=90
        )
        ax3.set_title("Overall Distribution of Verdicts")

        # Make percentage text bold
        for autotext in autotexts:
            autotext.set_fontweight("bold")
    else:
        ax3.text(
            0.5,
            0.5,
            "No data to display",
            ha="center",
            va="center",
            transform=ax3.transAxes,
        )
        ax3.set_title("Overall Distribution of Verdicts")

    # 4. Success Rate Chart
    ax4 = plt.subplot(2, 2, 4)
    success_rates = []
    for g, m, e in zip(goodware_counts, malware_counts, error_counts):
        total = g + m + e
        if total > 0:
            success_rate = ((g + m) / total) * 100  # Success = not an error
            success_rates.append(success_rate)
        else:
            success_rates.append(0)

    bars = ax4.bar(x, success_rates, color="skyblue", alpha=0.8)
    ax4.set_ylabel("Success Rate (%)")
    ax4.set_title("Success Rate by Category\n(Percentage of non-error responses)")
    ax4.set_xticks(x)
    ax4.set_xticklabels(labels, rotation=45, ha="right")
    ax4.set_ylim(0, 100)
    ax4.grid(True, alpha=0.3)

    # Add value labels on bars
    for i, rate in enumerate(success_rates):
        ax4.text(
            i, rate + 1, f"{rate:.1f}%", ha="center", va="bottom", fontweight="bold"
        )

    plt.tight_layout()

    # Save the plot
    plt.savefig("malware_analysis_results.png", dpi=300, bbox_inches="tight")
    print("Visualization saved as 'malware_analysis_results.png'")

    # Also create individual pie charts for each category
    create_individual_pie_charts(results)

    plt.show()


def create_individual_pie_charts(results):
    """
    Creates individual pie charts for each category.
    """
    fig, axes = plt.subplots(1, len(results), figsize=(5 * len(results), 4))
    if len(results) == 1:
        axes = [axes]

    for i, (path, data) in enumerate(results.items()):
        goodware = data["goodware"]
        malware = data["malware"]
        errors = data["errors"]

        sizes = [goodware, malware, errors]
        labels = ["Goodware", "Malware", "Errors"]
        colors = ["forestgreen", "firebrick", "orange"]

        # Only create pie chart if there are results
        if sum(sizes) > 0:
            wedges, texts, autotexts = axes[i].pie(
                sizes, labels=labels, colors=colors, autopct="%1.1f%%", startangle=90
            )
            axes[i].set_title(f"{os.path.basename(path)}\nTotal: {sum(sizes)} files")

            # Make percentage text bold
            for autotext in autotexts:
                autotext.set_fontweight("bold")
        else:
            axes[i].text(
                0.5,
                0.5,
                "No data",
                ha="center",
                va="center",
                transform=axes[i].transAxes,
            )
            axes[i].set_title(f"{os.path.basename(path)}\nNo data")

    plt.tight_layout()
    plt.savefig("individual_category_analysis.png", dpi=300, bbox_inches="tight")
    print("Individual category charts saved as 'individual_category_analysis.png'")
    plt.show()


if __name__ == "__main__":
    print("Starting malware analysis with 4 threads (optimized for localhost API)")
    print("Processing directories: crypt-only, pipeline-crypt, pipeline-packed")
    print("API endpoint: http://127.0.0.1:8080")
    print("-" * 60)

    main()
