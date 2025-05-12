# Phishing Email Detection Web App

This Flask-based application allows users to analyze potentially malicious emails using AI-based heuristics and phishing indicators.

## Features

- Upload suspicious email content
- Analyze sender, structure, and language
- Log results into SQLite database
- User authentication (optional)
- Future: AI-based explanation using Mistral via Ollama

## Getting Started

1. Clone the repo:
   ```bash
   git clone https://github.com/opulenceee/phishing-final-project.git
   cd phishing-final-project
   ```
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
3. Run the app:
   ```bash
   python app.py
   ```

## AI-Powered Email Analysis (Optional)

To enable AI-based phishing explanations using a local model (Mistral):

1. Install [Ollama] using the following link: (https://ollama.com/download)

2. Run:

   ```bash
   ollama pull mistral
   ollama run mistral
   ```

3. Set `USE_LOCAL_AI=true` in your `.env` file.
   Otherwise, the app will still work perfectly, just without AI explanations.
