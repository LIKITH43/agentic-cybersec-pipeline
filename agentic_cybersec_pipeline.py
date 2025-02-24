# agentic_cybersec_pipeline - Streamlit Deployment Version

import os
import logging
import streamlit as st
from langchain_community.chat_models import ChatOpenAI
from langgraph.graph import StateGraph
from typing import Dict, List, TypedDict

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

# Define state schema
class AuditState(TypedDict):
    instruction: str
    tasks: List[Dict]
    logs: List[str]

class SecurityAuditAgent:
    def __init__(self, scope: Dict[str, List[str]]):
        self.scope = scope
        self.task_list = []
        self.logs = []
        self.graph = self.build_graph()

    def build_graph(self):
        graph = StateGraph(AuditState)  # Use StateGraph for multiple paths
        graph.add_node("start", self.task_planner)
        graph.add_node("execute", self.execute_task)
        graph.add_node("done", lambda state: state)  # End node

        graph.add_edge("start", "execute")
        graph.add_edge("execute", "start")  # Loop if tasks remain
        graph.add_edge("execute", "done")  # Finish when no tasks remain

        graph.set_entry_point("start")  # Set correct entry point
        return graph.compile()  # Compile for execution

    def task_planner(self, state: AuditState):
        instruction = state["instruction"]
        logging.info(f"Processing instruction: {instruction}")

        # Simulating task planning
        self.task_list.append({"tool": "nmap", "target": self.scope["domains"][0], "params": "-Pn -p 80,443"})

        state["tasks"] = self.task_list
        return state

    def execute_task(self, state: AuditState):
        if not state["tasks"]:
            return state  # No more tasks, transition to "done"

        task = state["tasks"].pop(0)  # Process first task
        logging.info(f"Executing: {task}")
        output = f"Simulated output of {task['tool']} on {task['target']}"
        self.logs.append(output)

        state["logs"] = self.logs
        return state

    def run(self, instruction: str):
        initial_state = {"instruction": instruction, "tasks": [], "logs": []}
        return self.graph.invoke(initial_state)  # Correct invocation method

# Streamlit UI
st.title("Agentic Cybersecurity Pipeline")
st.sidebar.header("Define Scope")

domain = st.sidebar.text_input("Target Domain", "google.com")
ip_range = st.sidebar.text_input("IP Range", "192.168.1.0/24")

if st.sidebar.button("Start Scan"):
    scope = {"domains": [domain], "ips": [ip_range]}
    agent = SecurityAuditAgent(scope)
    
    st.subheader("Running Security Audit...")
    final_state = agent.run(f"Scan {domain} for open ports")

    for log in final_state["logs"]:
        st.write(f"**Log:** {log}")

st.sidebar.text("Logs will appear below after execution.")
