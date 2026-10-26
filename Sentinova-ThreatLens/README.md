# Sentinova ThreatLens
## Project overview
Sentinova ThreatLens is a local Cyber Threat Intelligence (CTI)
and Security Operations Center (SOC) dashboard prototype.
## Features
- Threat indicator dashboard and KPI cards
- Indicator search and filters
- Threat severity and indicator type charts
- CSV export of filtered indicators
- IOC investigation details and illustrative analyst guidance
- Incident status updates
- Recent activity log
- Dark SOC-style interface
## Technology
- Python
- Streamlit
- Pandas
- Plotly
## Run locally
1. Install Python 3.12 or a compatible Python version.
2. Open PowerShell in this project directory.
3. Activate the virtual environment:
   .\.venv\Scripts\Activate.ps1
4. Start the dashboard:
   python -m streamlit run app.py
5. Open http://localhost:8501 in your browser.
## Demo data and limitations
This version uses simulated indicators and simulated feed names.
Risk scores, confidence values, and analyst recommendations are
illustrative. No live threat feeds are connected.
Incident status and activity changes are held in the active
Streamlit session and are not stored in a persistent database.
This is a learning and demonstration prototype, not a
production security monitoring or detection system.
