============================================================
  ForensiTrace — Digital Forensic Evidence Analysis &
                 Timeline Reconstruction System
============================================================

Course   : CSDF-30117  Introduction to Digital Forensics
Semester : Spring 2026
Author   : [Your Name]    Student ID: [Your ID]
Instructor: Engr. Rafia Durrani

------------------------------------------------------------
PROJECT OVERVIEW
------------------------------------------------------------
ForensiTrace is a Python-based digital forensic investigation
tool built to analyse Autopsy-generated CSV timelines, extract
deep metadata from files and images (including EXIF and GPS),
verify file integrity through cryptographic hashing, and
generate professional PDF investigation reports.

------------------------------------------------------------
FOLDER STRUCTURE
------------------------------------------------------------

Forensic_Tool/
│
├── data/
│   └── timeline.csv          ← Place your Autopsy CSV here
│
├── output/
│   └── report.pdf            ← Generated reports saved here
│
├── src/
│   ├── main.py               ← GUI entry-point (run this)
│   └── analyzer.py           ← Core forensic engine
│
└── README.txt                ← This file

------------------------------------------------------------
REQUIREMENTS
------------------------------------------------------------
Python 3.10 or higher (3.12 recommended)

Install dependencies:
  pip install pillow reportlab pandas matplotlib

All other modules (tkinter, hashlib, csv, os, pathlib,
datetime, platform, mimetypes) are part of the Python
standard library.

------------------------------------------------------------
HOW TO RUN
------------------------------------------------------------
  cd Forensic_Tool/src
  python main.py

------------------------------------------------------------
FEATURES
------------------------------------------------------------
1. TIMELINE ANALYZER
   - Load any Autopsy-generated CSV file
   - Automatically detect and flag suspicious extensions
     (.exe, .bat, .ps1, .vbs, .dll, .scr …)
   - Keyword-based anomaly detection (password, secret, key …)
   - Chronological timeline reconstruction
   - Live search / filter within the table
   - "Show Suspicious Only" view

2. FILE & IMAGE METADATA ANALYZER
   - Analyse ANY file on your PC
   - Detects file type via magic bytes (not just extension)
   - Computes MD5, SHA-1, SHA-256 hashes
   - Extracts full EXIF data from JPEG/PNG/TIFF images:
       Camera make & model, DateTime, GPS coordinates,
       Image dimensions, exposure settings, and more
   - Timestamps: Created / Modified / Accessed
   - Flags hidden files, zero-byte files, suspicious types

3. HASH VERIFIER
   - Compute MD5 / SHA-1 / SHA-256 for any file
   - Paste an expected hash to verify file integrity
   - Instant MATCH / MISMATCH verdict

4. FORENSIC PDF REPORT GENERATOR
   - Professional, court-ready PDF report
   - Includes: case metadata, timeline summary,
     suspicious files list, file metadata, hash results
   - Selective section inclusion via checkboxes

------------------------------------------------------------
IMAGE METADATA (YOUR QUESTION)
------------------------------------------------------------
To analyse your own photos:
  1. Open the app → click "File / Image Metadata"
  2. Click Browse → select any .jpg/.jpeg/.png from your PC
  3. Click Analyze
  4. The right panel shows all EXIF data including:
       - Camera model & manufacturer
       - Date & time the photo was taken
       - GPS latitude / longitude (if available)
       - Image dimensions & colour mode
       - Software used to process the image
       - Orientation, flash, ISO, focal length, etc.

------------------------------------------------------------
SUBMISSION CHECKLIST
------------------------------------------------------------
[x] Source code (main.py, analyzer.py)
[ ] Project report (PDF)
[ ] Project flyer
[ ] 120-second demo video
[ ] South Punjab Hackathon submission (deadline: 1 May 2026)

------------------------------------------------------------
DISCLAIMER
------------------------------------------------------------
This tool is developed for educational purposes as part of
the IUB Spring 2026 Digital Forensics course project.
All forensic analysis must follow proper chain-of-custody
procedures when used in real investigations.
============================================================