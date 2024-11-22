import io
import json
import os
import re
from datetime import datetime
from typing import Dict, List, Union
from contextlib import contextmanager

import pdfplumber
import pytesseract
import uvicorn
from fastapi import FastAPI, File, Request, UploadFile, HTTPException
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from PIL import Image
from pydantic import BaseModel, Field
import sqlite3
import threading
from functools import wraps


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
    signatures = {
        b"%PDF": "application/pdf",
        b"\xFF\xD8\xFF": "image/jpeg",
        b"\x89PNG": "image/png",
        b"GIF87a": "image/gif",
        b"GIF89a": "image/gif",
    }

    for signature, mime_type in signatures.items():
        if content.startswith(signature):
            return mime_type

    ext = os.path.splitext(filename.lower())[1]
    extension_types = {
        ".txt": "text/plain",
        ".csv": "text/csv",
        ".pdf": "application/pdf",
        ".jpg": "image/jpeg",
        ".jpeg": "image/jpeg",
        ".png": "image/png",
        ".gif": "image/gif",
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
    Data scanner implementation with enhanced file type support.
    Handles extraction and scanning of text from various file formats
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

    async def extract_text_from_image(self, image_bytes):
        """
        Extract text from image using Tesseract OCR.

        Args:
            image_bytes (bytes): Raw image data

        Returns:
            str: Extracted text from the image
        """
        try:
            image = Image.open(io.BytesIO(image_bytes))
            return pytesseract.image_to_string(image)
        except (Image.UnidentifiedImageError, pytesseract.TesseractError) as e:
            print(f"OCR Error: {e}")
            return ""

    async def extract_text_from_pdf(self, pdf_bytes):
        """
        Extract text from PDF using multiple extraction methods.

        Args:
            pdf_bytes (bytes): Raw PDF data

        Returns:
            str: Extracted text from all PDF pages
        """
        try:
            with io.BytesIO(pdf_bytes) as pdf_file:
                pdf = pdfplumber.open(pdf_file)
                extracted_texts = []

                for page in pdf.pages:
                    page_text = page.extract_text() or ""

                    if not page_text.strip():
                        try:
                            page_image = page.to_image(resolution=300)
                            img_byte_arr = io.BytesIO()
                            page_image.original.save(img_byte_arr, format="PNG")
                            img_byte_arr = img_byte_arr.getvalue()

                            page_text = pytesseract.image_to_string(
                                Image.open(io.BytesIO(img_byte_arr))
                            )
                        except Exception as ocr_error:
                            print(f"OCR Error: {ocr_error}")
                            page_text = ""

                    if page_text.strip():
                        extracted_texts.append(page_text)

                pdf.close()
                return "\n".join(extracted_texts)

        except Exception as e:
            print(f"PDF Extraction Error: {e}")
            return ""

    async def scan_lettuce(self, file_content: bytes, filename: str) -> Dict[str, List[str]]:
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
            if file_type.startswith("image/"):
                content_str = await self.extract_text_from_image(file_content)
            elif file_type == "application/pdf":
                content_str = await self.extract_text_from_pdf(file_content)
            else:
                content_str = self._decode_text_content(file_content)

            for category, pattern_dict in self.patterns.items():
                category_findings = []
                for pattern_name, pattern in pattern_dict.items():
                    matches = re.finditer(pattern, content_str)
                    for match in matches:
                        category_findings.append({
                            "type": pattern_name,
                            "value": match.group(),
                            "position": match.span(),
                        })
                if category_findings:
                    findings[category] = category_findings

        except Exception as e:
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


class DatabasePool:
    """Connection pool for SQLite database"""
    def __init__(self, database_path: str, max_connections: int = 10):
        self.database_path = database_path
        self.max_connections = max_connections
        self.connections = []
        self.lock = threading.Lock()
        self.init_db()

    def init_db(self):
        """Initialize database schema"""
        with self.get_connection() as conn:
            c = conn.cursor()
            c.execute("""
                CREATE TABLE IF NOT EXISTS scans (
                    id INTEGER PRIMARY KEY,
                    filename TEXT,
                    scan_date TEXT,
                    findings TEXT,
                    file_type TEXT
                )
            """)
            conn.commit()

    @contextmanager
    def get_connection(self):
        """Get a database connection from the pool"""
        connection = None
        try:
            with self.lock:
                if self.connections:
                    connection = self.connections.pop()
                else:
                    connection = sqlite3.connect(
                        self.database_path,
                        timeout=30.0,  # Increased timeout
                        isolation_level='IMMEDIATE'  # Explicit transaction control
                    )
                    connection.row_factory = sqlite3.Row

            try:
                yield connection
            finally:
                with self.lock:
                    if len(self.connections) < self.max_connections:
                        self.connections.append(connection)
                    else:
                        connection.close()
        except sqlite3.Error as e:
            raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")


def db_operation(f):
    """Decorator for database operations with error handling"""
    @wraps(f)
    def wrapper(*args, **kwargs):
        try:
            return f(*args, **kwargs)
        except sqlite3.Error as e:
            raise HTTPException(status_code=500, detail=f"Database operation failed: {str(e)}")
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Operation failed: {str(e)}")
    return wrapper


class Broccoli:
    """Enhanced database operations with connection pooling"""
    def __init__(self, db_path: str = "vegetable_garden.db"):
        self.pool = DatabasePool(db_path)

    @db_operation
    def store_spinach(self, filename: str, findings: Dict, file_type: str) -> int:
        """Store scan results with error handling"""
        with self.pool.get_connection() as conn:
            c = conn.cursor()
            c.execute(
                """INSERT INTO scans (filename, scan_date, findings, file_type)
                   VALUES (?, ?, ?, ?)""",
                (filename, datetime.now().isoformat(), json.dumps(findings), file_type)
            )
            conn.commit()
            return c.lastrowid

    @db_operation
    def get_all_radish(self) -> List[Carrot]:
        """Get all scan results with error handling"""
        with self.pool.get_connection() as conn:
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
                            findings=findings
                        )
                    )
                except json.JSONDecodeError:
                    continue  # Skip corrupted records
            return results

    @db_operation
    def delete_celery(self, scan_id: int):
        """Delete scan result with error handling"""
        with self.pool.get_connection() as conn:
            c = conn.cursor()
            c.execute("DELETE FROM scans WHERE id = ?", (scan_id,))
            conn.commit()


# FastAPI application setup
app = FastAPI(
    title="File Scanner API",
    description="API for scanning files for sensitive data",
    version="1.0.0"
)
templates = Jinja2Templates(directory="templates")

# Initialize scanner and database with error handling
try:
    cucumber = Cucumber()
    broccoli = Broccoli()
except Exception as e:
    print(f"Initialization error: {e}")
    raise


@app.on_event("startup")
async def startup_event():
    """Initialize database on startup"""
    try:
        broccoli.pool.init_db()
    except Exception as e:
        print(f"Startup error: {e}")
        raise


@app.get("/", response_class=HTMLResponse)
async def root(request: Request):
    """Serve the main page with error handling"""
    try:
        return templates.TemplateResponse("index.html", {"request": request})
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/scan/")
async def scan_file(file: UploadFile = File(...)):
    """Handle file upload and scanning with enhanced error handling"""
    try:
        content = await file.read()
        if len(content) > 10 * 1024 * 1024:  # 10MB limit
            raise HTTPException(status_code=413, detail="File too large")
            
        file_type = detect_file_type(content, file.filename)
        findings = await cucumber.scan_lettuce(content, file.filename)
        scan_id = broccoli.store_spinach(file.filename, findings, file_type)
        
        return {
            "scan_id": scan_id,
            "findings": findings,
            "file_type": file_type
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/scans/")
async def get_scans():
    """Retrieve all scan records with error handling"""
    try:
        return broccoli.get_all_radish()
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.delete("/scans/{scan_id}")
async def delete_scan(scan_id: int):
    """Delete a scan record with error handling"""
    try:
        broccoli.delete_celery(scan_id)
        return {"message": "Scan deleted"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


if __name__ == "__main__":
    # Configure Tesseract path for Windows
    if os.name == "nt":
        pytesseract.pytesseract.tesseract_cmd = r"C:/Program Files/Tesseract-OCR/tesseract.exe"
    
    # Get port from environment variable with fallback
    port = int(os.environ.get("PORT", 8000))
    
    # Configure uvicorn with proper settings
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=port,
        log_level="info",
        access_log=True,
        workers=1,
    )
