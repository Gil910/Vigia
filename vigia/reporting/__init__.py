"""
VIGÍA — Reporting Module v0.1
Genera informes de campaña exportables en múltiples formatos.

Formatos soportados:
  - HTML: Informe interactivo con gráficos y tablas (standalone, sin deps externas)
  - JSON: Datos estructurados para integración con otros sistemas
  - Markdown: Para documentación, GitHub, o conversión a PDF

El módulo puede generar informes desde:
  1. La base de datos SQLite (campañas históricas)
  2. Datos en memoria (evaluaciones + remediación de la sesión actual)
"""

from vigia.reporting.generator import ReportGenerator, CampaignData

__all__ = ["ReportGenerator", "CampaignData"]
