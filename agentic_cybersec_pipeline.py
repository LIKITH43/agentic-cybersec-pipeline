# agentic_cybersec_pipeline - Streamlit Deployment Version

import os
import json
import logging
import streamlit as st
from langchain_community.chat_models import ChatOpenAI
from langgraph.graph import Graph
from typing import Dict, List

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

class SecurityAuditAgent:
    def __init__(self, scope: Dict[str, List[str]]):
        self.scope = scope
        self.task_list = []
        self.logs = []
        self.graph = self.build_graph()

    def build_graph(self):
        graph = Graph()
        graph.add_node("start", self.task_planner)
        graph.add_node("execute", self.execute_task)
        graph.add_edge("start", "execute")
        graph.add_edge("execute", "start")  # Loop until all tasks are done
        graph.set_entry_point("start")  # Correct way to set the entry point
        return graph

    def task_planner(self, state: Dict):
        instruction = state.get("instruction", "")
        logging.info(f"Processing instruction: {instruction}")
        self.task_list.append({"tool": "nmap", "target": "google.com", "params": "-Pn -p 80,443"})
        return {"next": "execute", "state": state}

    def execute_task(self, state: Dict):
        if not self.task_list:
            return {"next": "done", "state": state}
        task = self.task_list.pop(0)
        logging.info(f"Executing: {task}")
        output = f"Simulated output of {task['tool']} on {task['target']}"
        self.logs.append(output)
        return {"next": "start", "state": state}

    def run(self, instruction: str):
        result = self.graph.traverse({"instruction": instruction})


# Streamlit UI
st.title("Agentic Cybersecurity Pipeline")
st.sidebar.header("Define Scope")

domain = st.sidebar.text_input("Target Domain", "google.com")
ip_range = st.sidebar.text_input("IP Range", "192.168.1.0/24")

if st.sidebar.button("Start Scan"):
    scope = {"domains": [domain], "ips": [ip_range]}
    agent = SecurityAuditAgent(scope)
    st.subheader("Running Security Audit...")
    agent.run(f"Scan {domain} for open ports")
    for log in agent.logs:
        st.write(f"**Log:** {log}")

st.sidebar.text("Logs will appear below after execution.")
