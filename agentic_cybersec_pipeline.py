# streamlit_app.py
import streamlit as st
import subprocess
import time
import logging
import json
from typing import List, Dict, Any

from langgraph.graph import StateGraph, END
from langgraph.prebuilt import ToolExecutor
from langchain.agents import Tool
from langchain_core.messages import BaseMessage
from langchain_core.runnables import RunnableLambda
from langchain_openai import ChatOpenAI
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Initialize OpenAI model
llm = ChatOpenAI(model="gpt-4-1106-preview")

# Global scope (can be modified via Streamlit UI)
global_scope = {
    "domains": ["google.com"],
    "ips": ["8.8.8.8"]
}

# State definition
class AgentState:
    task: str = ""
    task_list: List[Dict[str, Any]] = []
    messages: List[BaseMessage] = []
    scope: Dict[str, List[str]] = global_scope
    results: Dict[str, str] = {}
    retries: Dict[str, int] = {}

# Utility functions (same as in main.py)
def run_command(command: List[str], scope: Dict[str, List[str]]) -> str:
    try:
        logging.info(f"Running command: {command}")
        if not is_in_scope(command, scope):
            return "Command execution blocked due to scope violation."
        result = subprocess.run(command, capture_output=True, text=True, timeout=60)
        if result.returncode == 0:
            logging.info(f"Command succeeded. Output: {result.stdout}")
            return result.stdout
        else:
            logging.error(f"Command failed. Error: {result.stderr}")
            return f"Command failed with error: {result.stderr}"
    except subprocess.TimeoutExpired:
        logging.error("Command timed out.")
        return "Command timed out."
    except Exception as e:
        logging.exception(f"Error running command: {e}")
        return f"Error: {e}"

def is_in_scope(command: List[str], scope: Dict[str, List[str]]) -> bool:
    for arg in command:
        if any(domain in arg for domain in scope["domains"]):
            return True
        if any(ip in arg for ip in scope["ips"]):
            return True
    logging.warning(f"Command {command} is out of scope.")
    return False

def parse_nmap_output(output: str) -> List[str]:
    open_ports = []
    for line in output.splitlines():
        if "/tcp" in line and "open" in line:
            port = line.split("/tcp")[0].strip()
            open_ports.append(port)
    return open_ports

def parse_gobuster_output(output: str) -> List[str]:
    directories = []
    for line in output.splitlines():
        if "Status: 200" in line or "Status: 301" in line:
            directory = line.split(" (Status:")[0].strip()
            directories.append(directory)
    return directories

# Tool definitions (same as in main.py)
def nmap_scan(target: str) -> str:
    command = ["nmap", target]
    return run_command(command, global_scope)

def gobuster_scan(target: str, wordlist: str = "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt") -> str:
    command = ["gobuster", "dir", "-u", target, "-w", wordlist]
    return run_command(command, global_scope)

def ffuf_scan(target: str, wordlist: str = "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt") -> str:
    command = ["ffuf", "-u", f"{target}/FUZZ", "-w", wordlist]
    return run_command(command, global_scope)

def sqlmap_scan(target: str) -> str:
    command = ["sqlmap", "-u", target]
    return run_command(command, global_scope)

tools = [
    Tool(name="nmap_scan", func=nmap_scan, description="Run an nmap scan on a target."),
    Tool(name="gobuster_scan", func=gobuster_scan, description="Run a gobuster scan on a target."),
    Tool(name="ffuf_scan", func=ffuf_scan, description="Run a ffuf scan on a target."),
    Tool(name="sqlmap_scan", func=sqlmap_scan, description="Run sqlmap on a target.")
