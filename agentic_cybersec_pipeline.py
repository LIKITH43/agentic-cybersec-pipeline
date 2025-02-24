import os
import logging
import streamlit as st
from langchain_community.chat_models import ChatOpenAI
from langgraph.graph import StateGraph
from typing import Dict, List, TypedDict, Annotated

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

# Define state schema
class AuditState(TypedDict):
    instruction: Annotated[str, "input_key"]  # Prevents duplicate values
    tasks: List[Dict]
    logs: List[str]

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
            if state["tasks"]:  # Continue execution
                return "execute"
            return "done"  # Stop when no tasks remain

        graph.add_conditional_edges("start", decide_next)
        graph.add_conditional_edges("execute", decide_next)  # Corrected transition
        graph.set_entry_point("start")  

        return graph.compile(config={"recursion_limit": 10})  # Explicit recursion limit

    def task_planner(self, state: AuditState):
        """Generate tasks only once"""
        if not state["tasks"]:  
            task = {"tool": "nmap", "target": self.scope["domains"][0], "params": "-Pn -p 80,443"}
            logging.info(f"Task Planned: {task}")
            state["tasks"] = [task]  
        return state

    def execute_task(self, state: AuditState):
        """Execute one task at a time"""
        if state["tasks"]:
            task = state["tasks"].pop(0)  # Take and remove one task
            logging.info(f"Executing: {task}")
            output = f"Simulated output of {task['tool']} on {task['target']}"
            state["logs"].append(output)
        return state

    def run(self, instruction: str):
        """Run the LangGraph pipeline"""
        initial_state = {"instruction": instruction, "tasks": [], "logs": []}
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
    final_state = agent.run(f"Scan {domain} for open ports")

    for log in final_state["logs"]:
        st.write(f"**Log:** {log}")

st.sidebar.text("Logs will appear below after execution.")
