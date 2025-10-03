#!/usr/bin/env python3
"""
Comprehensive model testing script that runs main.py against all 17 models
and creates aggregated visualizations comparing model performance.
"""

import subprocess
import time
import json
import os
import pandas as pd
import matplotlib.pyplot as plt
import numpy as np
from collections import defaultdict
import argparse
from datetime import datetime
import signal
import sys


class ModelTester:
    def __init__(self, timeout=300):
        self.threads = 4  # Optimal for localhost API
        self.timeout = timeout
        self.results = {}
        self.model_status = {}

    def kill_docker_containers_on_port(self, port=8080):
        """
        Kill any Docker containers using the specified port
        """
        try:
            # Find containers using the port
            result = subprocess.run(
                ["docker", "ps", "--filter", f"publish={port}", "--format", "{{.ID}}"],
                capture_output=True,
                text=True,
            )

            if result.returncode == 0 and result.stdout.strip():
                container_ids = result.stdout.strip().split("\n")
                for container_id in container_ids:
                    if container_id:
                        print(f"Killing container {container_id} using port {port}")
                        subprocess.run(
                            ["docker", "kill", container_id],
                            capture_output=True,
                            text=True,
                        )
                        time.sleep(2)  # Give it time to stop
        except Exception as e:
            print(f"WARNING: Could not clean up containers on port {port}: {e}")

    def run_model_test(self, model_id):
        """
        Run a single model test by starting docker container and running main.py
        """
        print(f"\n{'='*60}")
        print(f"Testing Model {model_id}")
        print(f"{'='*60}")

        # Clean up any existing containers on port 8080 first
        self.kill_docker_containers_on_port(8080)
        time.sleep(2)

        docker_cmd = [
            "docker",
            "run",
            "--rm",
            "--memory=1g",
            "-p",
            "8080:8080",
            f"team_{model_id}",
        ]

        docker_process = None
        try:
            # Start the docker container
            print(f"Starting Docker container for team_{model_id}...")
            docker_process = subprocess.Popen(
                docker_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
            )

            # Wait for container to start up
            print("Waiting for API to be ready...")
            time.sleep(4)  # Give container time to start

            # Check if container is still running
            if docker_process.poll() is not None:
                stdout, stderr = docker_process.communicate()
                print(f"ERROR: Docker container failed to start:")
                print(f"STDOUT: {stdout}")
                print(f"STDERR: {stderr}")
                return None

            # Run the main.py script
            print(f"Running malware analysis against model {model_id}...")
            main_cmd = ["python3", "main.py"]

            result = subprocess.run(
                main_cmd, capture_output=True, text=True, timeout=self.timeout
            )

            if result.returncode == 0:
                print(f"SUCCESS: Model {model_id} completed successfully")
                self.model_status[model_id] = "success"
                return self.parse_results(result.stdout)
            else:
                print(
                    f"ERROR: Model {model_id} failed with return code {result.returncode}"
                )
                print(f"STDERR: {result.stderr}")
                self.model_status[model_id] = "failed"
                return None

        except subprocess.TimeoutExpired:
            print(f"TIMEOUT: Model {model_id} timed out after {self.timeout} seconds")
            self.model_status[model_id] = "timeout"
            return None
        except Exception as e:
            print(f"ERROR: Unexpected error testing model {model_id}: {e}")
            self.model_status[model_id] = "error"
            return None
        finally:
            # Kill the docker container process
            if docker_process:
                print(f"Stopping Docker container for model {model_id}...")
                try:
                    docker_process.terminate()
                    docker_process.wait(timeout=5)
                    print("Container stopped")
                except subprocess.TimeoutExpired:
                    docker_process.kill()
                    docker_process.wait(timeout=2)
                    print("Container killed")
                except Exception as e:
                    print(f"Error stopping container: {e}")
                    try:
                        docker_process.kill()
                    except:
                        pass

    def parse_results(self, output):
        """
        Parse the output from main.py to extract results for the out directory
        """
        results = {
            "out": {"goodware": 0, "malware": 0, "errors": 0},
        }

        lines = output.split("\n")
        current_category = None

        for line in lines:
            if "Results for" in line:
                if "out" in line:
                    current_category = "out"
            elif current_category and "Goodware" in line:
                try:
                    count = int(line.split(":")[1].split()[0])
                    results[current_category]["goodware"] = count
                except:
                    pass
            elif current_category and "Malware" in line:
                try:
                    count = int(line.split(":")[1].split()[0])
                    results[current_category]["malware"] = count
                except:
                    pass
            elif current_category and "Errors" in line:
                try:
                    count = int(line.split(":")[1].split()[0])
                    results[current_category]["errors"] = count
                except:
                    pass

        return results

    def run_all_models(self, start_model=1, end_model=17):
        """
        Run tests against all models from start_model to end_model
        """
        print(f"Starting comprehensive model testing")
        print(f"Testing models {start_model} through {end_model}")
        print(f"Using 4 threads per model (optimized for localhost API)")
        print(f"Timeout: {self.timeout} seconds per model")

        # Clean up any existing containers on port 8080
        print(f"Cleaning up any existing containers on port 8080...")
        self.kill_docker_containers_on_port(8080)
        time.sleep(3)  # Give it time to clean up

        for model_id in range(start_model, end_model + 1):
            if model_id in [2, 3, 11, 13, 14, 15]:
                continue
            print(
                f"\nProgress: {model_id - start_model + 1}/{end_model - start_model + 1}"
            )

            result = self.run_model_test(model_id)
            if result:
                self.results[model_id] = result
                print(f"Model {model_id} results collected")
            else:
                print(f"Model {model_id} results not available")

        print(
            f"\nTesting complete! {len(self.results)}/{end_model - start_model + 1} models successful"
        )

        # Final cleanup
        print(f"Final cleanup of any remaining containers...")
        self.kill_docker_containers_on_port(8080)

        return self.results

    def save_results(self, filename="model_test_results.json"):
        """
        Save results to JSON file
        """
        data = {
            "timestamp": datetime.now().isoformat(),
            "threads_per_model": 4,  # Fixed optimal value
            "model_status": self.model_status,
            "results": self.results,
        }

        with open(filename, "w") as f:
            json.dump(data, f, indent=2)

        print(f"Results saved to {filename}")

    def create_comprehensive_visualization(self):
        """
        Create comprehensive visualizations comparing all models
        """
        if not self.results:
            print("ERROR: No results to visualize")
            return

        print("Creating comprehensive visualizations...")

        # Create main comparison dashboard
        self.create_model_comparison_dashboard()

        # Create category-specific analysis
        self.create_category_analysis()

        # Create evasion analysis
        self.create_evasion_analysis()

        # Create model performance summary
        self.create_performance_summary()

    def create_model_comparison_dashboard(self):
        """
        Create a comprehensive dashboard comparing all models for the out directory
        """
        models = sorted(self.results.keys())
        category = "out"

        fig, axes = plt.subplots(2, 2, figsize=(20, 15))
        fig.suptitle(
            "Comprehensive Model Performance Analysis - Out Directory",
            fontsize=16,
            fontweight="bold",
        )

        # 1. Detection Rates by Model
        ax1 = axes[0, 0]
        detection_rates = []
        for model in models:
            data = self.results[model][category]
            total_files = data["goodware"] + data["malware"] + data["errors"]
            if total_files > 0:
                detection_rate = (data["malware"] / total_files) * 100
                detection_rates.append(detection_rate)
            else:
                detection_rates.append(0)

        bars = ax1.bar(range(len(models)), detection_rates, color="skyblue", alpha=0.7)
        ax1.set_xlabel("Model ID")
        ax1.set_ylabel("Detection Rate (%)")
        ax1.set_title("Malware Detection Rate by Model (Out Directory)")
        ax1.set_xticks(range(len(models)))
        ax1.set_xticklabels([f"Model {m}" for m in models], rotation=45)
        ax1.grid(True, alpha=0.3)

        # Add value labels
        for i, rate in enumerate(detection_rates):
            ax1.text(
                i,
                rate + 0.5,
                f"{rate:.1f}%",
                ha="center",
                va="bottom",
                fontweight="bold",
            )

        # 2. Goodware vs Malware Counts
        ax2 = axes[0, 1]
        goodware_counts = []
        malware_counts = []
        for model in models:
            data = self.results[model][category]
            goodware_counts.append(data["goodware"])
            malware_counts.append(data["malware"])

        x = np.arange(len(models))
        width = 0.35

        bars1 = ax2.bar(
            x - width / 2,
            goodware_counts,
            width,
            label="Goodware",
            color="green",
            alpha=0.7,
        )
        bars2 = ax2.bar(
            x + width / 2,
            malware_counts,
            width,
            label="Malware",
            color="red",
            alpha=0.7,
        )

        ax2.set_xlabel("Model ID")
        ax2.set_ylabel("File Count")
        ax2.set_title("Goodware vs Malware Detection Counts")
        ax2.set_xticks(x)
        ax2.set_xticklabels([f"Model {m}" for m in models], rotation=45)
        ax2.legend()
        ax2.grid(True, alpha=0.3)

        # Add value labels
        for bar in bars1:
            height = bar.get_height()
            ax2.text(
                bar.get_x() + bar.get_width() / 2.0,
                height + 0.5,
                f"{int(height)}",
                ha="center",
                va="bottom",
                fontweight="bold",
            )
        for bar in bars2:
            height = bar.get_height()
            ax2.text(
                bar.get_x() + bar.get_width() / 2.0,
                height + 0.5,
                f"{int(height)}",
                ha="center",
                va="bottom",
                fontweight="bold",
            )

        # 3. Error Rates by Model
        ax3 = axes[1, 0]
        error_rates = []
        for model in models:
            data = self.results[model][category]
            total_files = data["goodware"] + data["malware"] + data["errors"]
            if total_files > 0:
                error_rate = (data["errors"] / total_files) * 100
                error_rates.append(error_rate)
            else:
                error_rates.append(0)

        bars = ax3.bar(range(len(models)), error_rates, color="orange", alpha=0.7)
        ax3.set_xlabel("Model ID")
        ax3.set_ylabel("Error Rate (%)")
        ax3.set_title("API Error Rate by Model")
        ax3.set_xticks(range(len(models)))
        ax3.set_xticklabels([f"Model {m}" for m in models], rotation=45)
        ax3.grid(True, alpha=0.3)

        # Add value labels
        for i, rate in enumerate(error_rates):
            ax3.text(
                i,
                rate + 0.5,
                f"{rate:.1f}%",
                ha="center",
                va="bottom",
                fontweight="bold",
            )

        # 4. Model Success Summary
        ax4 = axes[1, 1]
        successful_models = len(
            [m for m in models if self.model_status.get(m) == "success"]
        )
        failed_models = len(
            [m for m in models if self.model_status.get(m) != "success"]
        )

        sizes = [successful_models, failed_models]
        labels = ["Successful", "Failed/Error"]
        colors = ["lightgreen", "lightcoral"]

        wedges, texts, autotexts = ax4.pie(
            sizes, labels=labels, colors=colors, autopct="%1.1f%%", startangle=90
        )
        ax4.set_title(
            f"Model Test Success Rate\n({successful_models}/{len(models)} models)"
        )

        for autotext in autotexts:
            autotext.set_fontweight("bold")

        plt.tight_layout()
        plt.savefig("comprehensive_model_analysis.png", dpi=300, bbox_inches="tight")
        print("Comprehensive analysis saved as 'comprehensive_model_analysis.png'")
        plt.show()

    def create_category_analysis(self):
        """
        Create detailed analysis for the out directory
        """
        models = sorted(self.results.keys())
        category = "out"

        fig, ax = plt.subplots(1, 1, figsize=(12, 8))
        fig.suptitle(
            "Detailed Analysis - Out Directory", fontsize=16, fontweight="bold"
        )

        detection_rates = []
        for model in models:
            data = self.results[model][category]
            total = data["goodware"] + data["malware"] + data["errors"]
            if total > 0:
                rate = (data["malware"] / total) * 100
            else:
                rate = 0
            detection_rates.append(rate)

        bars = ax.bar(
            range(len(models)),
            detection_rates,
            color=[
                "red" if r < 50 else "orange" if r < 80 else "green"
                for r in detection_rates
            ],
            alpha=0.7,
        )

        ax.set_xlabel("Model ID")
        ax.set_ylabel("Detection Rate (%)")
        ax.set_title("Malware Detection Rate by Model\n(Out Directory)")
        ax.set_xticks(range(len(models)))
        ax.set_xticklabels([f"M{m}" for m in models], rotation=45)
        ax.grid(True, alpha=0.3)
        ax.set_ylim(0, 100)

        # Add value labels
        for j, rate in enumerate(detection_rates):
            ax.text(
                j,
                rate + 1,
                f"{rate:.1f}%",
                ha="center",
                va="bottom",
                fontweight="bold",
            )

        plt.tight_layout()
        plt.savefig("out_directory_analysis.png", dpi=300, bbox_inches="tight")
        print("Out directory analysis saved as 'out_directory_analysis.png'")
        plt.show()

    def create_evasion_analysis(self):
        """
        Create analysis showing which models are best evaded for the out directory
        """
        models = sorted(self.results.keys())
        category = "out"

        # Calculate evasion scores (lower detection rate = better evasion)
        evasion_scores = []
        detection_rates = []

        for model in models:
            data = self.results[model][category]
            total = data["goodware"] + data["malware"] + data["errors"]
            if total > 0:
                detection_rate = (data["malware"] / total) * 100
                evasion_score = 100 - detection_rate  # Higher = better evasion
            else:
                detection_rate = 0
                evasion_score = 0
            detection_rates.append(detection_rate)
            evasion_scores.append(evasion_score)

        # Create visualization
        fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(16, 6))
        fig.suptitle("Evasion Analysis - Out Directory", fontweight="bold", fontsize=16)

        # 1. Detection Rate Heatmap-style
        colors = [
            "red" if r < 50 else "orange" if r < 80 else "green"
            for r in detection_rates
        ]
        bars1 = ax1.bar(range(len(models)), detection_rates, color=colors, alpha=0.7)
        ax1.set_xlabel("Model ID")
        ax1.set_ylabel("Detection Rate (%)")
        ax1.set_title("Detection Rate by Model")
        ax1.set_xticks(range(len(models)))
        ax1.set_xticklabels([f"Model {m}" for m in models], rotation=45)
        ax1.grid(True, alpha=0.3)
        ax1.set_ylim(0, 100)

        # Add value labels
        for i, rate in enumerate(detection_rates):
            ax1.text(
                i, rate + 1, f"{rate:.1f}%", ha="center", va="bottom", fontweight="bold"
            )

        # 2. Evasion Score
        colors2 = [
            "green" if s > 50 else "orange" if s > 20 else "red" for s in evasion_scores
        ]
        bars2 = ax2.bar(range(len(models)), evasion_scores, color=colors2, alpha=0.7)
        ax2.set_xlabel("Model ID")
        ax2.set_ylabel("Evasion Score (%)")
        ax2.set_title("Evasion Effectiveness\n(Higher = Better Evasion)")
        ax2.set_xticks(range(len(models)))
        ax2.set_xticklabels([f"Model {m}" for m in models], rotation=45)
        ax2.grid(True, alpha=0.3)
        ax2.set_ylim(0, 100)

        # Add value labels
        for i, score in enumerate(evasion_scores):
            ax2.text(
                i,
                score + 1,
                f"{score:.1f}%",
                ha="center",
                va="bottom",
                fontweight="bold",
            )

        plt.tight_layout()
        plt.savefig("evasion_analysis_out_directory.png", dpi=300, bbox_inches="tight")
        print("Evasion analysis saved as 'evasion_analysis_out_directory.png'")
        plt.show()

    def create_performance_summary(self):
        """
        Create a summary table of model performance for the out directory
        """
        models = sorted(self.results.keys())
        category = "out"

        # Create summary data
        summary_data = []
        for model in models:
            data = self.results[model][category]
            total_files = data["goodware"] + data["malware"] + data["errors"]

            # Detection rate
            if total_files > 0:
                detection_rate = (data["malware"] / total_files) * 100
                error_rate = (data["errors"] / total_files) * 100
            else:
                detection_rate = 0
                error_rate = 0

            row = {
                "Model": f"Model {model}",
                "Detection_Rate": f"{detection_rate:.1f}%",
                "Goodware_Count": data["goodware"],
                "Malware_Count": data["malware"],
                "Error_Count": data["errors"],
                "Total_Files": total_files,
                "Error_Rate": f"{error_rate:.1f}%",
                "Status": self.model_status.get(model, "unknown"),
            }
            summary_data.append(row)

        # Create DataFrame and save
        df = pd.DataFrame(summary_data)
        df.to_csv("model_performance_summary_out_directory.csv", index=False)
        print(
            "Performance summary saved as 'model_performance_summary_out_directory.csv'"
        )

        # Print summary to console
        print("\n" + "=" * 100)
        print("MODEL PERFORMANCE SUMMARY - OUT DIRECTORY")
        print("=" * 100)
        print(df.to_string(index=False))
        print("=" * 100)


def main():
    parser = argparse.ArgumentParser(
        description="Test all models against malware samples"
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=300,
        help="Timeout per model in seconds (default: 300)",
    )
    parser.add_argument(
        "--start-model", type=int, default=1, help="Starting model number (default: 1)"
    )
    parser.add_argument(
        "--end-model", type=int, default=17, help="Ending model number (default: 17)"
    )

    args = parser.parse_args()

    # Create tester instance (uses 4 threads by default)
    tester = ModelTester(timeout=args.timeout)

    try:
        # Run all model tests
        results = tester.run_all_models(args.start_model, args.end_model)

        # Save results
        tester.save_results()

        # Create visualizations
        tester.create_comprehensive_visualization()

        print(f"\nAnalysis complete! Check the generated files:")
        print("comprehensive_model_analysis.png")
        print("out_directory_analysis.png")
        print("evasion_analysis_out_directory.png")
        print("model_performance_summary_out_directory.csv")
        print("model_test_results.json")

    except KeyboardInterrupt:
        print("\nAnalysis interrupted by user")
        tester.save_results("interrupted_results.json")
    except Exception as e:
        print(f"\nUnexpected error: {e}")
        tester.save_results("error_results.json")


if __name__ == "__main__":
    main()
