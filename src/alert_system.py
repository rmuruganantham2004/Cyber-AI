import pandas as pd
import json
from datetime import datetime

class AlertSystem:
    def __init__(self, log_file="data/processed/alerts.log"):
        self.log_file = log_file
        
    def generate_alerts(self, df):
        """Generate alerts for logs classified as CRITICAL."""
        print("Checking for critical threats to alert...")
        
        critical_logs = df[df['severity'] == 'CRITICAL']
        alerts_generated = 0
        
        with open(self.log_file, "a") as f:
            for _, row in critical_logs.iterrows():
                alert = {
                    "alert_time": datetime.now().isoformat(),
                    "event_timestamp": row['timestamp'],
                    "source_ip": row['source_ip'],
                    "dest_ip": row['dest_ip'],
                    "user": row['user'],
                    "event_type": row['event_type'],
                    "message": row['message'],
                    "risk_score": float(row['overall_risk_score']),
                    "severity": row['severity']
                }
                
                # Mock sending an email/SMS
                self._send_notification(alert)
                
                # Write to log
                f.write(json.dumps(alert) + "\n")
                alerts_generated += 1
                
        print(f"Generated {alerts_generated} alerts. Saved to {self.log_file}")
        
    def _send_notification(self, alert_data):
        """Mock function to simulate sending email or SMS."""
        # In a real scenario, integrate with Twilio or SendGrid here
        msg = f"[ALERT] {alert_data['severity']} Threat Detected: {alert_data['user']} from {alert_data['source_ip']}. Score: {alert_data['risk_score']:.2f}"
        print(msg)

if __name__ == "__main__":
    try:
        df = pd.read_csv("data/processed/final_threat_scores.csv")
    except FileNotFoundError:
        print("Final threat scores not found.")
        exit(1)
        
    alerter = AlertSystem()
    alerter.generate_alerts(df)
