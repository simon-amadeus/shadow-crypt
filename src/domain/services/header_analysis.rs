//! Example of how domain services can use the TLV parser trait generically
//! This demonstrates the architectural improvement achieved by the refactoring.

use crate::domain::services::tlv_parser::{TlvParser, TlvParsingError};
use crate::domain::entities::tlv_header::TlvHeader;

/// Generic domain service that can work with any TLV parser implementation
pub struct HeaderAnalysisService;

impl HeaderAnalysisService {
    /// Analyze a file's header using any TLV parser implementation
    /// This shows how domain services are now decoupled from infrastructure
    pub fn analyze_header<P: TlvParser>(file_data: &[u8]) -> Result<HeaderAnalysis, TlvParsingError> {
        let (header, remaining_data) = P::parse_header_with_remainder(file_data)?;
        
        Ok(HeaderAnalysis {
            header_size: file_data.len() - remaining_data.len(),
            ciphertext_size: remaining_data.len(),
            has_filename: header.original_filename().is_some(),
            has_content_hash: header.content_hash().is_some(),
            algorithm_id: header.algorithm_id(),
            field_count: header.fields.len(),
        })
    }
    
    /// Validate header data using domain validation rules
    pub fn validate_header_fields<P: TlvParser>(header: &TlvHeader) -> Result<(), TlvParsingError> {
        // Check filename if present
        if let Some(filename) = header.original_filename() {
            P::validate_field_data(0x01, filename.as_bytes())?;
        }
        
        // Check content hash if present
        if let Some(hash) = header.content_hash() {
            P::validate_field_data(0x07, &hash)?;
        }
        
        // Validate algorithm ID if present
        if let Some(algo_id) = header.algorithm_id() {
            P::validate_field_data(0x08, &[algo_id])?;
        }
        
        Ok(())
    }
}

#[derive(Debug, PartialEq)]
pub struct HeaderAnalysis {
    pub header_size: usize,
    pub ciphertext_size: usize,
    pub has_filename: bool,
    pub has_content_hash: bool,
    pub algorithm_id: Option<u8>,
    pub field_count: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::infrastructure::tlv_serialization::TlvSerializer;
    use crate::domain::entities::tlv_header::TlvHeader;
    
    #[test]
    fn test_generic_header_analysis() {
        // Create test data
        let mut header = TlvHeader::new();
        header.set_original_filename("test.txt");
        header.set_algorithm_id(1);
        header.set_content_hash([0x42u8; 32]);
        
        let header_bytes = TlvSerializer::serialize_header(&header).unwrap();
        let mut file_data = header_bytes.clone();
        file_data.extend_from_slice(b"encrypted content");
        
        // Analyze using generic service
        let analysis = HeaderAnalysisService::analyze_header::<TlvSerializer>(&file_data).unwrap();
        
        assert_eq!(analysis.header_size, header_bytes.len());
        assert_eq!(analysis.ciphertext_size, b"encrypted content".len());
        assert!(analysis.has_filename);
        assert!(analysis.has_content_hash);
        assert_eq!(analysis.algorithm_id, Some(1));
        assert_eq!(analysis.field_count, 3); // filename, algorithm_id, content_hash
    }
    
    #[test]
    fn test_domain_validation() {
        let mut header = TlvHeader::new();
        header.set_original_filename("test.txt");
        header.set_algorithm_id(1);
        
        // Should pass validation
        HeaderAnalysisService::validate_header_fields::<TlvSerializer>(&header).unwrap();
    }
}