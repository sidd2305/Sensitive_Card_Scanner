import pytest
import os
import re
import sqlite3
import tempfile
from unittest.mock import patch, MagicMock
from typing import Dict, List, Union
import io
import json
from PIL import Image
import pytesseract
# import pdfplumber

# Import the classes and functions to test
from main import (
    Cucumber, 
    Broccoli, 
    Carrot, 
    detect_file_type
)

@pytest.fixture
def temp_db():
    """Create a temporary database for testing"""
    with tempfile.NamedTemporaryFile(delete=False) as temp_file:
        db_path = temp_file.name
    
    broccoli = Broccoli(db_path)
    yield broccoli
    
    # Clean up
    os.unlink(db_path)

def test_detect_file_type():
    """Test file type detection"""
    # PDF signature
    assert detect_file_type(b'%PDF-1.5', 'test.pdf') == 'application/pdf'
    
    # JPEG signature
    assert detect_file_type(b'\xFF\xD8\xFF', 'test.jpg') == 'image/jpeg'
    
    # PNG signature
    assert detect_file_type(b'\x89PNG', 'test.png') == 'image/png'
    
    # File extension detection
    assert detect_file_type(b'random content', 'test.txt') == 'text/plain'
    assert detect_file_type(b'random content', 'test.csv') == 'text/csv'
    
    # Fallback detection
    assert detect_file_type(b'random content', 'test.unknown') == 'application/octet-stream'

@pytest.mark.asyncio
async def test_cucumber_scan():
    """Test Cucumber's scan_lettuce method"""
    cucumber = Cucumber()
    
    # Test text content scanning
    text_content = "My PAN is ABCDE1234F and email is test@example.com"
    findings = await cucumber.scan_lettuce(text_content.encode(), 'test.txt')
    
    assert 'PII' in findings
    assert len(findings['PII']) == 2
    assert any(finding['type'] == 'PAN' for finding in findings['PII'])
    assert any(finding['type'] == 'EMAIL' for finding in findings['PII'])

@pytest.mark.asyncio
async def test_cucumber_image_extraction(tmp_path):
    """Test image text extraction"""
    cucumber = Cucumber()
    
    # Create a test image
    test_image = Image.new('RGB', (100, 100), color='red')
    image_path = tmp_path / 'test.png'
    test_image.save(image_path)
    
    with patch('pytesseract.image_to_string', return_value='Test OCR Text'):
        text = await cucumber.extract_text_from_image(open(image_path, 'rb').read())
        assert text == 'Test OCR Text'

@pytest.mark.asyncio
async def test_cucumber_pdf_extraction(tmp_path):
    """Test PDF text extraction"""
    cucumber = Cucumber()
    
    # Create a mock PDF
    mock_pdf_path = tmp_path / 'test.pdf'
    with open(mock_pdf_path, 'wb') as f:
        f.write(b'%PDF-1.5 mock content')
    
    with patch('pdfplumber.open') as mock_pdf_opener:
        mock_page = MagicMock()
        mock_page.extract_text.return_value = 'Test PDF Text'
        mock_pdf = MagicMock()
        mock_pdf.pages = [mock_page]
        mock_pdf_opener.return_value.__enter__.return_value = mock_pdf
        
        text = await cucumber.extract_text_from_pdf(open(mock_pdf_path, 'rb').read())
        assert text == 'Test PDF Text'

def test_broccoli_store_and_retrieve(temp_db):
    """Test storing and retrieving scan results"""
    # Store a scan result
    test_findings = {
        'PII': [{'type': 'EMAIL', 'value': 'test@example.com'}]
    }
    scan_id = temp_db.store_spinach('test.txt', test_findings, 'text/plain')
    
    # Retrieve results
    results = temp_db.get_all_radish()
    
    assert len(results) > 0
    latest_result = results[-1]
    assert latest_result.filename == 'test.txt'
    assert latest_result.findings == test_findings

def test_broccoli_delete(temp_db):
    """Test deleting a scan result"""
    # Store a scan result
    test_findings = {
        'PII': [{'type': 'EMAIL', 'value': 'test@example.com'}]
    }
    scan_id = temp_db.store_spinach('test.txt', test_findings, 'text/plain')
    
    # Delete the scan
    temp_db.delete_celery(scan_id)
    
    # Verify deletion
    results = temp_db.get_all_radish()
    assert all(result.file_id != scan_id for result in results)

def test_carrot_model():
    """Test Carrot model creation"""
    carrot = Carrot(
        file_id=1, 
        filename='test.txt', 
        scan_date='2024-01-01T00:00:00',
        findings={'PII': [{'type': 'EMAIL', 'value': 'test@example.com'}]}
    )
    
    assert carrot.file_id == 1
    assert carrot.filename == 'test.txt'
    assert carrot.scan_date == '2024-01-01T00:00:00'
    assert 'PII' in carrot.findings

def test_sensitive_pattern_matching():
    """Test comprehensive sensitive data pattern matching"""
    cucumber = Cucumber()
    test_cases = {
        'PAN': ['ABCDE1234F', 'QWERT6789P'],
        'SSN': ['123-45-6789', '987-65-4321'],
        'EMAIL': ['user@example.com', 'john.doe@company.co.uk'],
        'PHONE': ['+911234567890', '9876543210'],
        'MEDICAL_RECORD': ['MR12345678'],
        'HEALTH_INSURANCE': ['HI1234567890'],
        'BLOOD_TYPE': ['A+', 'B-', 'AB+'],
        'CREDIT_CARD': ['1234-5678-9012-3456', '4111 1111 1111 1111'],
        'CVV': ['CVV: 123', 'CVV:456'],
        'EXPIRY': ['12/25', '01/30']
    }
    
    for category, patterns in test_cases.items():
        for pattern in patterns:
            # Find the category in cucumber patterns that contains this pattern type
            found = False
            for cat_name, cat_patterns in cucumber.patterns.items():
                if category in cat_patterns:
                    # Test if the pattern matches the regex
                    if re.match(cat_patterns[category], pattern):
                        found = True
                        break
            assert found, f"Pattern {pattern} of type {category} was not matched by any regex"