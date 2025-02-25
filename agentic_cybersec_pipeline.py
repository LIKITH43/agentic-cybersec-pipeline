import os
import logging
import subprocess
import streamlit as st
from langgraph.graph import StateGraph
from typing import Dict, List, TypedDict, Annotated
from dotenv import load_dotenv
import time
import random

# Load environment variables
load_dotenv()

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

# Define state schema
class AuditState(TypedDict):
    instruction: Annotated[str, "input_key"]  # High-level instruction
    tasks: List[Dict]  # List of tasks to execute
    logs: List[str]  # Execution logs
    scope: Dict[str, List[str]]  # User-defined scope

class SecurityAuditAgent:
    def __init__(self, scope: Dict[str, List[str]]):
        self.scope = scope
        self.graph = self.build_graph()

    def build_graph(self):
        graph = StateGraph(AuditState)
        graph.add_node("start", self.task_planner)
        graph.add_node("execute", self.execute_task)
        graph.add_node("done", lambda state: state)  # Final state

        # **Termination condition**
        def decide_next(state):
            if state["tasks"]:  # Continue execution if tasks remain
                return "execute"
            return "done"  # Stop when no tasks remain

        graph.add_conditional_edges("start", decide_next)
        graph.add_conditional_edges("execute", decide_next)
        graph.set_entry_point("start")

        return graph.compile()

    def task_planner(self, state: AuditState):
        """Generate initial tasks based on the instruction"""
        if not state["tasks"]:
            instruction = state["instruction"]
            if "scan" in instruction.lower() and "ports" in instruction.lower():
                # Add nmap task
                state["tasks"].append({
                    "tool": "nmap",
                    "target": self.scope["domains"][0],
                    "params": "-Pn -p 80,443,22,8080",
                })
            if "discover directories" in instruction.lower():
                # Add gobuster task
                state["tasks"].append({
                    "tool": "gobuster",
                    "target": self.scope["domains"][0],
                    "params": "dir -u http://{target} -w /usr/share/wordlists/dirb/common.txt",
                })
            logging.info(f"Tasks Planned: {state['tasks']}")
        return state

    def execute_task(self, state: AuditState):
        """Execute one task at a time"""
        if state["tasks"]:
            task = state["tasks"].pop(0)  # Take and remove one task
            logging.info(f"Executing: {task}")
            try:
                output = self.run_tool(task)
                state["logs"].append(output)
                # Dynamically add new tasks based on output
                if task["tool"] == "nmap":
                    # Example: Add gobuster task if HTTP ports are open
                    if "80/tcp" in output or "443/tcp" in output:
                        state["tasks"].append({
                            "tool": "gobuster",
                            "target": task["target"],
                            "params": "dir -u http://{target} -w /usr/share/wordlists/dirb/common.txt",
                        })
            except Exception as e:
                logging.error(f"Task failed: {e}")
                state["logs"].append(f"Task failed: {task} - {str(e)}")
        return state

    def run_tool(self, task: Dict):
        """Simulate running a security tool and return realistic output"""
        tool = task["tool"]
        target = task["target"]
        params = task["params"].format(target=target)
        command = f"{tool} {params}"
        logging.info(f"Running command: {command}")

        # Simulate realistic output based on the tool
        if tool == "nmap":
            output = self.simulate_nmap(target)
        elif tool == "gobuster":
            output = self.simulate_gobuster(target)
        else:
            output = f"Simulated output for {tool} on {target} with params {params}"

        return output

    def simulate_nmap(self, target: str):
        """Simulate nmap output"""
        output = [
            f"Starting Nmap scan on {target}...",
            "Scanning ports: 80, 443, 22, 8080",
            "Discovered open ports:",
            "80/tcp  - HTTP",
            "443/tcp - HTTPS",
            "22/tcp  - SSH",
            "8080/tcp - HTTP-Alt",
            "Nmap scan completed.",
        ]
        return "\n".join(output)

    def simulate_gobuster(self, target: str):
        """Simulate gobuster output"""
        output = [
            f"Starting Gobuster scan on {target}...",
            "Found directories:",
            "/admin",
            "/login",
            "/images",
            "/assets",
            "Gobuster scan completed.",
        ]
        return "\n".join(output)

    def run(self, instruction: str):
        """Run the LangGraph pipeline"""
        initial_state = {"instruction": instruction, "tasks": [], "logs": [], "scope": self.scope}
        return self.graph.invoke(initial_state)

# Streamlit UI
st.title("Agentic Cybersecurity Pipeline")
st.sidebar.header("Define Scope")

domain = st.sidebar.text_input("Target Domain", "google.com")
ip_range = st.sidebar.text_input("IP Range", "192.168.1.0/24")

if st.sidebar.button("Start Scan"):
    scope = {"domains": [domain], "ips": [ip_range]}
    agent = SecurityAuditAgent(scope)
    
    st.subheader("Running Security Audit...")
    final_state = agent.run(f"Scan {domain} for open ports and discover directories")

    # Display logs with unique keys
    for i, log in enumerate(final_state["logs"]):
        st.text_area(f"Log {i + 1}", log, height=200, key=f"log_{i}")

st.sidebar.text("Logs will appear below after execution.")
