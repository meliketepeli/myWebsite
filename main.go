package main

import (
	"github.com/gofiber/fiber/v2"
	"newProject/app"
	"newProject/configs"
	"newProject/repository"
	"newProject/services"
)

func main() {

	appRoute := fiber.New()
	configs.ConnectDB()

	dbClient := configs.GetCollection(configs.DB, "Products")

	ProductRepositoryDB := repository.NewProductRepositoryDB(dbClient)

	pr := app.ProductHandler{services.NewProductService(ProductRepositoryDB)}

	appRoute.Post("/api/product", pr.CreateProduct)
	appRoute.Get("/api/products", pr.GetAllProduct)
	appRoute.Delete("/api/product/:id", pr.DeleteProduct)
	appRoute.Listen(":8080")

}
