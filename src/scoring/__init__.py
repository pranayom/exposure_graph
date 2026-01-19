"""
Risk scoring module for ExposureGraph.

Provides explainable risk calculations for web services based on
observable security indicators.
"""

from .calculator import RiskCalculator

__all__ = ["RiskCalculator"]
