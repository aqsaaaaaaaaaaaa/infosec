#!/usr/bin/env python3
"""Convert PROJECT_REPORT.md to PDF"""

from reportlab.lib.pagesizes import letter, A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, KeepTogether
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_JUSTIFY
import re

# Read markdown
with open('PROJECT_REPORT.md', 'r') as f:
    content = f.read()

# Create PDF
pdf_path = 'PROJECT_REPORT.pdf'
doc = SimpleDocTemplate(pdf_path, pagesize=letter, topMargin=0.5*inch, bottomMargin=0.5*inch)
story = []

# Styles
styles = getSampleStyleSheet()
title_style = ParagraphStyle(
    'CustomTitle',
    parent=styles['Heading1'],
    fontSize=24,
    textColor=colors.HexColor('#1f3a93'),
    spaceAfter=12,
    alignment=TA_CENTER
)
heading1_style = ParagraphStyle(
    'CustomHeading1',
    parent=styles['Heading1'],
    fontSize=16,
    textColor=colors.HexColor('#1f3a93'),
    spaceAfter=10,
    spaceBefore=10
)
heading2_style = ParagraphStyle(
    'CustomHeading2',
    parent=styles['Heading2'],
    fontSize=13,
    textColor=colors.HexColor('#2d5aa0'),
    spaceAfter=8,
    spaceBefore=8
)
body_style = ParagraphStyle(
    'CustomBody',
    parent=styles['BodyText'],
    fontSize=10,
    alignment=TA_JUSTIFY,
    spaceAfter=6
)

# Parse markdown manually
lines = content.split('\n')
i = 0
while i < len(lines):
    line = lines[i].rstrip()
    
    # Title (# heading)
    if line.startswith('# ') and not line.startswith('##'):
        title = line[2:].strip()
        story.append(Paragraph(title, title_style))
        story.append(Spacer(1, 0.2*inch))
        i += 1
        continue
    
    # Heading 2 (## heading)
    if line.startswith('## '):
        heading = line[3:].strip()
        story.append(Paragraph(heading, heading1_style))
        story.append(Spacer(1, 0.1*inch))
        i += 1
        continue
    
    # Heading 3 (### heading)
    if line.startswith('### '):
        heading = line[4:].strip()
        story.append(Paragraph(heading, heading2_style))
        story.append(Spacer(1, 0.08*inch))
        i += 1
        continue
    
    # Code blocks (```...```)
    if line.startswith('```'):
        code_lines = []
        i += 1
        while i < len(lines) and not lines[i].startswith('```'):
            code_lines.append(lines[i])
            i += 1
        code_text = '\n'.join(code_lines)
        code_style = ParagraphStyle(
            'Code',
            parent=styles['Normal'],
            fontSize=8,
            fontName='Courier',
            textColor=colors.HexColor('#333333'),
            backColor=colors.HexColor('#f5f5f5'),
            leftIndent=10,
            spaceAfter=6
        )
        for line in code_text.split('\n'):
            if line.strip():
                story.append(Paragraph(line, code_style))
        story.append(Spacer(1, 0.1*inch))
        i += 1
        continue
    
    # Tables (markdown tables)
    if '|' in line and i+1 < len(lines) and '---' in lines[i+1]:
        table_lines = [line]
        i += 1
        table_lines.append(lines[i])  # separator
        i += 1
        while i < len(lines) and '|' in lines[i]:
            table_lines.append(lines[i])
            i += 1
        
        # Parse table
        rows = []
        for idx, tline in enumerate(table_lines):
            if '---' not in tline:
                cells = [cell.strip() for cell in tline.split('|')[1:-1]]
                rows.append(cells)
        
        if rows:
            table = Table(rows, colWidths=[1.5*inch]*len(rows[0]))
            table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1f3a93')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 9),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 8),
                ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                ('GRID', (0, 0), (-1, -1), 1, colors.black),
                ('FONTSIZE', (0, 1), (-1, -1), 8),
            ]))
            story.append(table)
            story.append(Spacer(1, 0.15*inch))
        continue
    
    # Regular paragraphs
    if line.strip() and not line.startswith(('- ', '* ', '`', '|')):
        if '---' not in line:  # Skip separator lines
            story.append(Paragraph(line.strip(), body_style))
            story.append(Spacer(1, 0.05*inch))
    
    # Bullet points
    if line.startswith(('- ', '* ')):
        bullet = line[2:].strip()
        story.append(Paragraph('• ' + bullet, body_style))
        story.append(Spacer(1, 0.05*inch))
    
    i += 1

# Build PDF
doc.build(story)
print(f"✅ PDF created: {pdf_path}")
