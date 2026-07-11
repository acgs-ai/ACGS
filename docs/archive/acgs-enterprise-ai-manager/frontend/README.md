# ACGS Enterprise Manager - Frontend

Vue.js frontend application for the ACGS Enterprise Manager system.

## Features

- Vue 3 with Composition API
- Vue Router for navigation
- Pinia for state management
- Axios for API communication
- Vite for fast development and building

## Project Structure

```
frontend/
├── src/
│   ├── api/          # API client configuration
│   ├── assets/       # Static assets and styles
│   ├── components/   # Reusable Vue components
│   ├── router/       # Vue Router configuration
│   ├── store/        # Pinia stores
│   ├── views/        # Page components
│   ├── App.vue       # Root component
│   └── main.js       # Application entry point
├── index.html
├── package.json
└── vite.config.js
```

## Development

```bash
# Install dependencies
npm install

# Start development server
npm run dev

# Build for production
npm run build

# Preview production build
npm run preview
```

## Domain Views

The application includes CRUD interfaces for 6 domains:

1. **Tasks** - Task management with status and priority tracking
2. **IT Assets** - Hardware, software, and license management
3. **Infrastructure** - Server, network, storage, and cloud infrastructure
4. **Projects** - Project lifecycle management
5. **Financial** - Income and expense tracking
6. **Documents** - Document management with categorization

## Authentication

The application uses JWT token-based authentication. Tokens are stored in localStorage and automatically included in API requests.

## API Integration

The frontend connects to the FastAPI backend at `http://localhost:8000`. API endpoints are proxied through Vite during development.

All API calls go through `/api/v1` prefix and include:
- Automatic token injection
- Error handling with 401 redirect
- Request/response interceptors
