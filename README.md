
# Create env & run it 
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# Copy env and set secrets
cp config/.env.example .env
# edit .env (SMTP host, email, etc.)

# Install stuff
pip install -r requirements.txt

# Run on a pcap
python -m src.cli --pcap samples/sample.pcapng --blacklist config/blacklist.txt

# deactivate venv
deactivate