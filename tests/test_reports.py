import os
import tempfile
import unittest

from export import export_html, export_pdf


def sample_report_data():
    return {
        "history": [42, "portal.interno.local", "2026-07-24 14:30:00", "completed"],
        "summary": [
            42,
            42,
            "80/tcp open http\n443/tcp open https\nServer: nginx",
            (
                "La evaluación identificó una debilidad crítica de control de acceso y "
                "configuraciones de transporte mejorables. Se recomienda contener la "
                "exposición crítica de inmediato y completar un re-test."
            ),
            "CRITICAL",
            "2026-07-24 14:45:00",
        ],
        "vulns": [
            [1, 42, "Control de acceso insuficiente", "critical", "443", "https",
             "Un usuario de bajo privilegio pudo consultar recursos administrativos mediante una referencia directa."],
            [2, 42, "Política HSTS ausente", "medium", "443", "https",
             "La respuesta HTTPS no incluyó Strict-Transport-Security."],
            [3, 42, "Divulgación de versión del servidor", "low", "80", "http",
             "La cabecera Server expuso información de versión útil para reconocimiento."],
        ],
        "fixes": [
            [1, 42, 1, "Aplicar autorización por objeto en el servidor, negar por defecto y agregar pruebas de regresión.", "PenTool"],
            [2, 42, 2, "Habilitar HSTS con una vigencia gradual y validar primero todos los subdominios.", "PenTool"],
            [3, 42, 3, "Eliminar tokens de versión de cabeceras y páginas de error.", "PenTool"],
        ],
        "exploits": [
            [1, 42, "Validación controlada de acceso", "HTTP", "GET /admin/users/2",
             "Confirmado en entorno autorizado", "Sin modificación de datos"],
        ],
        "events": [],
        "commands": [
            [1, "scan-42", "curl -I https://portal.interno.local",
             "HTTP/2 200\nserver: nginx\ncontent-type: text/html", "portal.interno.local",
             "2026-07-24 14:34:00"],
        ],
        "include_exploitation": True,
        "include_commands": True,
    }


class ReportExportTests(unittest.TestCase):
    def test_pdf_and_html_exports_are_created(self):
        with tempfile.TemporaryDirectory() as output_dir:
            data = sample_report_data()
            pdf_path = export_pdf(data, output_dir)
            html_path = export_html(data, output_dir)

            self.assertTrue(os.path.isfile(pdf_path))
            self.assertGreater(os.path.getsize(pdf_path), 10_000)
            self.assertTrue(os.path.isfile(html_path))
            with open(html_path, encoding="utf-8") as report:
                html = report.read()
            self.assertIn("Resumen ejecutivo", html)
            self.assertIn("OWASP WSTG", html)
            self.assertIn("Control de acceso insuficiente", html)


if __name__ == "__main__":
    unittest.main()
