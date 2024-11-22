import io
import json
import os
import re
import traceback
import sqlite3
from datetime import datetime
from typing import Dict, List, Union

import pdfplumber
import pytesseract
import uvicorn
from fastapi import FastAPI, File, Request, UploadFile, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from PIL import Image, ImageEnhance, ImageFilter
from pydantic import BaseModel, Field

class Carrot(BaseModel):
    file_id: int
    filename: str
    scan_date: str
    findings: Union[Dict[str, List[Dict[str, Union[str, tuple]]]], Dict] = Field(default_factory=dict)

def detect_file_type(content: bytes, filename: str) -> str:
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

    return extension_types.get(ext, "application/octet-stream")

class Cucumber:
    def __init__(self):
        self.patterns = {
            "PII": {
                "EMAIL": r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
                "PHONE": r"\+?1?\d{9,15}",
            },
            "PHI": {
                "MEDICAL_RECORD": r"MR\d{8}",
                "HEALTH_INSURANCE": r"HI\d{10}",
            },
            "PCI": {
                "CREDIT_CARD": r"\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}",
                "CVV": r"CVV:?\s*\d{3,4}",
            }
        }

    def _preprocess_image(self, image):
        processed_image = image.convert('L')
        processed_image = processed_image.filter(ImageFilter.SHARPEN)
        enhancer = ImageEnhance.Contrast(processed_image)
        return enhancer.enhance(2.0)

    async def extract_text_from_image(self, image_bytes):
        try:
            with Image.open(io.BytesIO(image_bytes)) as img:
                processed_img = self._preprocess_image(img)
                return pytesseract.image_to_string(processed_img)
        except Exception as e:
            print(f"OCR Error: {e}")
            return ""

    async def extract_text_from_pdf(self, pdf_bytes):
        try:
            with pdfplumber.open(io.BytesIO(pdf_bytes)) as pdf:
                return "\n".join([
                    page.extract_text() or 
                    pytesseract.image_to_string(page.to_image(resolution=300).original) 
                    for page in pdf.pages if page.extract_text() or 
                    pytesseract.image_to_string(page.to_image(resolution=300).original)
                ])
        except Exception as e:
            print(f"PDF Extraction Error: {e}")
            return ""

    async def scan_lettuce(self, file_content: bytes, filename: str) -> Dict:
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
                category_findings = [
                    {"type": pattern_name, "value": match.group(), "position": match.span()}
                    for pattern_name, pattern in pattern_dict.items()
                    for match in re.finditer(pattern, content_str)
                ]
                if category_findings:
                    findings[category] = category_findings

        except Exception as e:
            print(f"Scan Error: {traceback.format_exc()}")
            findings["error"] = [{"type": "scan_error", "value": str(e)}]

        return findings

    def _decode_text_content(self, content: bytes) -> str:
        for encoding in ["utf-8", "latin-1", "cp1252"]:
            try:
                return content.decode(encoding)
            except UnicodeDecodeError:
                continue
        return content.decode("cp1252", errors="ignore")

class Broccoli:
    def __init__(self, db_path: str = "vegetable_garden.db"):
        self.db_path = db_path
        self.init_db()

    def init_db(self):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS scans (
                    id INTEGER PRIMARY KEY,
                    filename TEXT,
                    scan_date TEXT,
                    findings TEXT,
                    file_type TEXT
                )
            """)

    def store_spinach(self, filename: str, findings: Dict, file_type: str) -> int:
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "INSERT INTO scans (filename, scan_date, findings, file_type) VALUES (?, ?, ?, ?)",
                    (filename, datetime.now().isoformat(), json.dumps(findings), file_type)
                )
                return cursor.lastrowid
        except sqlite3.Error as e:
            print(f"Database error: {e}")
            raise

app = FastAPI()
templates = Jinja2Templates(directory="templates")
cucumber = Cucumber()
broccoli = Broccoli()

@app.get("/", response_class=HTMLResponse)
async def root(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})

@app.post("/scan/")
async def scan_file(file: UploadFile = File(...)):
    try:
        content = await file.read(10 * 1024 * 1024)  # 10MB limit
        file_type = detect_file_type(content, file.filename)
        findings = await cucumber.scan_lettuce(content, file.filename)
        scan_id = broccoli.store_spinach(file.filename, findings, file_type)

        return {
            "scan_id": scan_id,
            "findings": findings,
            "file_type": file_type
        }
    except Exception as e:
        return JSONResponse(status_code=500, content={
            "error": f"Processing failed: {str(e)}",
            "details": traceback.format_exc()
        })

@app.get("/scans/")
async def get_scans():
    try:
        with sqlite3.connect(broccoli.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM scans")
            rows = cursor.fetchall()

        return [
            Carrot(
                file_id=row[0],
                filename=row[1],
                scan_date=row[2],
                findings=json.loads(row[3]) if row[3] else {}
            ) for row in rows
        ]
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
