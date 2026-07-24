# PenTool - Interfaz Web

## 🎨 Dashboard Hermoso y Sofisticado

Se ha creado una interfaz web moderna y profesional para PenTool con un diseño cybersecurity temático.

### 📁 Estructura de Archivos

```
frontend/
├── index.html          # Página principal del dashboard
├── css/
│   └── style.css       # Estilos sofisticados (tema oscuro + neon)
├── js/
│   └── app.js          # Lógica del cliente + consumo de API
└── img/                # Carpeta para imágenes (opcional)
```

### ✨ Características del Dashboard

#### 1. **Interfaz Hermosa**
- Tema oscuro profesional con colores neon (cian, magenta, verde)
- Animaciones suaves y transiciones elegantes
- Diseño responsive (funciona en escritorio, tablet y móvil)
- Gradientes modernos y sombras sofisticadas

#### 2. **Componentes Principales**

**Navbar:**
- Logo PenTool con animación pulsante
- Menú de navegación con iconos
- Área de usuario

**Sidebar:**
- Estado del sistema (API, Base de Datos, LLM)
- Estadísticas rápidas (escaneos, vulnerabilidades, críticas)

**Dashboard:**
- Widget de escaneo rápido
- Lista de escaneos recientes
- Gráficos de nivel de amenaza (Chart.js)
- Resumen de vulnerabilidades por severidad
- Registro de actividad en tiempo real

#### 3. **Navegación**
- **Dashboard**: Vista general y estadísticas
- **Nuevo Escaneo**: Configurar y ejecutar escaneos
- **Historial**: Ver todos los escaneos previos
- **Configuración**: Gestionar API keys y preferencias

### 🚀 Cómo Usar

#### 1. **Iniciar el Servidor**

```bash
# En la carpeta del proyecto
python main.py
```

El servidor estará disponible en: `http://localhost:8000`

#### 2. **Acceder al Dashboard**

Abre tu navegador y ve a:
```
http://localhost:8000/
```

#### 3. **Iniciar un Escaneo**

1. En el widget "Iniciar Nuevo Escaneo", ingresa:
   - IP: `192.168.1.1`
   - O Dominio: `example.com`

2. Haz clic en **"Escanear"**

3. El escaneo se ejecutará en segundo plano

#### 4. **Ver Resultados**

- Los escaneos completados aparecerán en **"Escaneos Recientes"**
- Haz clic en un escaneo para ver detalles
- Las vulnerabilidades se mostrarán con su severidad y recomendaciones

### 🎯 Endpoints de la API

La interfaz consume estos endpoints:

```
POST   /token              → Autenticación JWT
POST   /scan               → Iniciar escaneo
GET    /history            → Obtener historial
GET    /vulnerabilities    → Obtener vulnerabilidades
POST   /exploit            → Ejecutar exploits
POST   /ssh                → Ejecutar comandos SSH
POST   /report             → Generar reportes
```

### 🔒 Autenticación

Usa la API key por defecto:
```
api_key: pentool-api-key
```

### 🎨 Personalización de Colores

En `frontend/css/style.css`, puedes cambiar los colores CSS:

```css
:root {
    --primary: #00d9ff;           /* Cian */
    --secondary: #ff006e;         /* Magenta */
    --success: #00d084;           /* Verde */
    --danger: #ff4444;            /* Rojo */
    --warning: #ffaa00;           /* Naranja */
    --dark-bg: #0a0e27;           /* Fondo oscuro */
}
```

### 📊 Gráficos

El dashboard incluye:
- Gráfico de pastel de niveles de amenaza
- Indicadores de severidad (Crítica/Alta/Media/Baja)
- Log de actividad en tiempo real

### 📱 Responsive Design

- **Escritorio**: Diseño de 2-3 columnas
- **Tablet**: Diseño adaptado
- **Móvil**: Diseño de una columna

### 🔧 Requisitos

El servidor FastAPI ya tiene configurado:
- ✅ CORS (para peticiones desde el frontend)
- ✅ Static Files (para servir frontend)
- ✅ JWT Authentication
- ✅ API Key validation

### 📝 Notas

- La interfaz se conecta a `http://localhost:8000`
- Los datos se guardan en la base de datos MariaDB
- Los escaneos se ejecutan en segundo plano
- Las notificaciones toast informan sobre el estado

### 🎬 Próximos Pasos

Para mejorar aún más:

1. Agregar exportación de reportes directamente desde el dashboard
2. Agregar mapas de calor de vulnerabilidades
3. Agregar integración con webhooks
4. Agregar modo claro/oscuro toggle
5. Agregar búsqueda y filtros avanzados
6. Agregar soporte multiusuario

---

¡Disfruta tu dashboard PenTool! 🛡️⚡
