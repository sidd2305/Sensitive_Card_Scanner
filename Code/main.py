import io
import json
import os
import re
import sqlite3
from datetime import datetime
from typing import Dict, List, Union

import pdfplumber
import uvicorn
from fastapi import FastAPI, File, Request, UploadFile
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, Field


class Carrot(BaseModel):
    """
    Data model for scan results.

    Attributes:
        file_id (int): Unique identifier for the scanned file
        filename (str): Name of the scanned file
        scan_date (str): ISO format date string of when the scan was performed
        findings (Dict): Dictionary containing scan results with pattern matches
    """

    file_id: int
    filename: str
    scan_date: str
    findings: Union[Dict[str, List[Dict[str, Union[str, tuple]]]], Dict] = Field(
        default_factory=dict
    )


def detect_file_type(content: bytes, filename: str) -> str:
    """
    Detect the MIME type of a file based on its content and filename.

    Args:
        content (bytes): File content as bytes
        filename (str): Original filename with extension

    Returns:
        str: MIME type of the file
    """
    # Common file signatures (magic numbers)
    signatures = {
        b"%PDF": "application/pdf",
    }

    # Check file signatures
    for signature, mime_type in signatures.items():
        if content.startswith(signature):
            return mime_type

    # Check file extension if no signature match
    ext = os.path.splitext(filename.lower())[1]
    extension_types = {
        ".txt": "text/plain",
        ".csv": "text/csv",
        ".pdf": "application/pdf",
        ".doc": "application/msword",
        ".docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    }

    if ext in extension_types:
        return extension_types[ext]

    try:
        content.decode("utf-8")
        if ext in [".txt", ".csv", ".log", ".md"]:
            return "text/plain"
    except UnicodeDecodeError:
        pass

    return "application/octet-stream"


class Cucumber:
    """
    Data scanner implementation with PDF support.
    Handles extraction and scanning of text from PDFs and text files
    for sensitive data patterns.
    """

    def __init__(self):
        self.patterns = {
            "PII": {
                "PAN": r"[A-Z]{5}[0-9]{4}[A-Z]{1}",  # Indian PAN
                "SSN": r"\d{3}-\d{2}-\d{4}",  # US SSN
                "EMAIL": r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
                "PHONE": r"\+?1?\d{9,15}",
                "DOB": r"\b\d{2}/\d{2}/\d{4}\b",  # Matches DOB in format nn/nn/nn
                "AADHAAR": r"\b\d{4} \d{4} \d{4}\b",  # Matches Aadhaar in format #### #### ####
            },
            "PHI": {
                "MEDICAL_RECORD": r"MR\d{8}",
                "HEALTH_INSURANCE": r"HI\d{10}",
                "BLOOD_TYPE": r"(A|B|AB|O)[+-]",
            },
            "PCI": {
                "CREDIT_CARD": r"\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}",
                "CVV": r"CVV:?\s*\d{3,4}",
                "EXPIRY": r"^(0[1-9]|1[0-2])/([0-9]{2})$",
            },
        }

    async def extract_text_from_pdf(self, pdf_bytes):
        """
        Extract text from PDF using pdfplumber.

        Args:
            pdf_bytes (bytes): Raw PDF data

        Returns:
            str: Extracted text from all PDF pages
        """
        try:
            with io.BytesIO(pdf_bytes) as pdf_file:
                with pdfplumber.open(pdf_file) as pdf:
                    extracted_texts = []
                    for page in pdf.pages:
                        text = page.extract_text() or ""
                        if text.strip():
                            extracted_texts.append(text)
                    return "\n".join(extracted_texts)
        except Exception as e:
            print(f"PDF Extraction Error: {e}")
            return ""

    async def scan_lettuce(
        self, file_content: bytes, filename: str
    ) -> Dict[str, List[str]]:
        """
        Scan content for sensitive data with file type detection.

        Args:
            file_content (bytes): Raw file content
            filename (str): Original filename

        Returns:
            Dict[str, List[str]]: Dictionary of findings by category
        """
        findings = {}
        file_type = detect_file_type(file_content, filename)

        try:
            if file_type == "application/pdf":
                content_str = await self.extract_text_from_pdf(file_content)
            else:
                content_str = self._decode_text_content(file_content)

            for category, pattern_dict in self.patterns.items():
                category_findings = []
                for pattern_name, pattern in pattern_dict.items():
                    matches = re.finditer(pattern, content_str)
                    for match in matches:
                        category_findings.append(
                            {
                                "type": pattern_name,
                                "value": match.group(),
                                "position": match.span(),
                            }
                        )
                if category_findings:
                    findings[category] = category_findings

        except (UnicodeError, IOError) as e:
            print(f"Scan Error: {str(e)}")
            findings["error"] = [{"type": "scan_error", "value": str(e)}]

        return findings

    def _decode_text_content(self, content: bytes) -> str:
        """
        Attempt to decode binary content as text using multiple encodings.

        Args:
            content (bytes): Raw file content

        Returns:
            str: Decoded text content
        """
        encodings = ["utf-8", "latin-1", "cp1252"]
        for encoding in encodings:
            try:
                return content.decode(encoding)
            except UnicodeDecodeError:
                continue
        return content.decode("cp1252", errors="ignore")


class Broccoli:
    """Database operations for storing and retrieving scan results."""

    def __init__(self, db_path: str = "vegetable_garden.db"):
        self.db_path = db_path
        self.init_db()

    def init_db(self):
        """Initialize database tables and ensure schema is up-to-date."""
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()

        c.execute(
            """
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY,
                filename TEXT,
                scan_date TEXT,
                findings TEXT
            )
        """
        )

        try:
            c.execute("ALTER TABLE scans ADD COLUMN file_type TEXT;")
        except sqlite3.OperationalError:
            pass

        conn.commit()
        conn.close()

    def store_spinach(self, filename: str, findings: Dict, file_type: str) -> int:
        """
        Store scan results with file type.

        Args:
            filename (str): Name of the scanned file
            findings (Dict): Scan results
            file_type (str): MIME type of the file

        Returns:
            int: ID of the stored scan record
        """
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()

        c.execute(
            "INSERT INTO scans (filename, scan_date, findings, file_type) VALUES (?, ?, ?, ?)",
            (filename, datetime.now().isoformat(), json.dumps(findings), file_type),
        )

        scan_id = c.lastrowid
        conn.commit()
        conn.close()
        return scan_id

    def get_all_radish(self) -> List[Carrot]:
        """
        Get all scan results.

        Returns:
            List[Carrot]: List of all scan records
        """
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()

        c.execute("SELECT * FROM scans")
        rows = c.fetchall()

        results = []
        for row in rows:
            try:
                findings = json.loads(row[3]) if row[3] else {}
                results.append(
                    Carrot(
                        file_id=row[0],
                        filename=row[1],
                        scan_date=row[2],
                        findings=findings,
                    )
                )
            except json.JSONDecodeError as e:
                print(f"Error processing row {row[0]}: {e}")
                continue

        conn.close()
        return results

    def delete_celery(self, scan_id: int):
        """
        Delete scan result by ID.

        Args:
            scan_id (int): ID of the scan record to delete
        """
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute("DELETE FROM scans WHERE id = ?", (scan_id,))
        conn.commit()
        conn.close()


# FastAPI application
app = FastAPI()
templates = Jinja2Templates(directory="templates")

# Initialize scanner and database
cucumber = Cucumber()
broccoli = Broccoli()


@app.get("/", response_class=HTMLResponse)
async def root(request: Request):
    """Serve the main page."""
    return templates.TemplateResponse("index.html", {"request": request})


@app.post("/scan/")
async def scan_file(file: UploadFile = File(...)):
    """
    Handle file upload and scanning.

    Args:
        file (UploadFile): Uploaded file

    Returns:
        dict: Scan results including findings and file type
    """
    try:
        content = await file.read()
        print(f"File name: {file.filename}, Size: {len(content)} bytes")
        file_type = detect_file_type(content, file.filename)
        print(f"Detected file type: {file_type}")
        findings = await cucumber.scan_lettuce(content, file.filename)
        print(f"Findings: {findings}")
        scan_id = broccoli.store_spinach(file.filename, findings, file_type)

        return {"scan_id": scan_id, "findings": findings, "file_type": file_type}
    except (IOError, UnicodeError, sqlite3.Error) as e:
        return {"error": f"Error processing file: {str(e)}"}


@app.get("/scans/")
async def get_scans():
    """
    Retrieve all scan records.

    Returns:
        List[Carrot]: List of all scan records
    """
    return broccoli.get_all_radish()


@app.delete("/scans/{scan_id}")
async def delete_scan(scan_id: int):
    """
    Delete a scan record.

    Args:
        scan_id (int): ID of the scan to delete

    Returns:
        dict: Confirmation message
    """
    broccoli.delete_celery(scan_id)
    return {"message": "Scan deleted"}


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.1", port=8000)
