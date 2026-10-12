window.addEventListener("DOMContentLoaded", () => {
  if (!window.SwaggerUIBundle) {
    document.getElementById("swagger-ui").textContent = "Swagger UI failed to load. The OpenAPI specification is available in openapi.yaml.";
    return;
  }
  window.SwaggerUIBundle({
    url: "./openapi.yaml",
    dom_id: "#swagger-ui",
    deepLinking: true,
    displayRequestDuration: true,
    persistAuthorization: false,
    tryItOutEnabled: false,
    presets: [window.SwaggerUIBundle.presets.apis],
    layout: "BaseLayout"
  });
});
