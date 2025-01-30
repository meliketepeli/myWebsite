package routes

import (
	"github.com/gofiber/fiber/v2"
	"newProject/app" // Burada app paketini import etmelisin
)

func SetupRoutes(app *fiber.App, pr app.ProductHandler) {

	app.Get("/api/products", pr.GetAllProduct)
	app.Post("/api/products", pr.CreateProduct)
	app.Delete("/api/products/:id", pr.DeleteProduct)
}
