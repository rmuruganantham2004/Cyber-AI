import os
import subprocess
import sys

def run_script(script_path):
    print(f"\n{'='*50}\nRunning {script_path}...\n{'='*50}")
    result = subprocess.run([sys.executable, script_path])
    if result.returncode != 0:
        print(f"Error occurred while running {script_path}")
        sys.exit(1)

def main():
    # Make sure we are in the project root
    os.makedirs("data/raw", exist_ok=True)
    os.makedirs("data/processed", exist_ok=True)
    
    scripts = [
        "src/parser.py",
        "src/nlp_processor.py",
        "src/anomaly_detector.py",
        "src/graph_builder.py",
        "src/gnn_model.py",
        "src/threat_engine.py",
        "src/alert_system.py"
    ]
    
    for script in scripts:
        run_script(script)
        
    print("\nPipeline execution complete! You can now run the dashboard or API.")
    print("To run the dashboard: streamlit run dashboard/app.py")
    print("To run the API: uvicorn api.main:app --reload")

if __name__ == "__main__":
    main()
