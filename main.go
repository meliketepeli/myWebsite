package main

import (
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"newProject/app"
	"newProject/configs"
	"newProject/repository"
	"newProject/routes"
	"newProject/services"
)

func main() {

	// appRoute := fiber.New()
	configs.ConnectDB()

	// HTML template engine'i yükle
	engine := html.New("./templates", ".html") // templates klasörünü ayarla,

	// Fiber uygulamasını başlat ve engine'i ekle
	app := fiber.New(fiber.Config{
		Views: engine,
	})

	// CORS middleware ekle (frontend bağlanabilsin diye)
	app.Use(cors.New(cors.Config{
		AllowOrigins: "*",
		AllowMethods: "GET,POST,PUT,DELETE",
		AllowHeaders: "Origin, Content-Type, Accept",
	}))

	// Database bağlantısını başlat
	configs.ConnectDB()
	dbClient := configs.GetCollection(configs.DB, "Products")
	ProductRepositoryDB := repository.NewProductRepositoryDB(dbClient)
	service := services.NewProductService(ProductRepositoryDB)
	handler := app.ProductHandler{Service: service}

	// Routes'ları ayarla
	routes.SetupRoutes(app, handler)

	app.Static("/static", "./static")

	// HTML sayfasını render eden bir route ekle
	app.Get("/products", func(c *fiber.Ctx) error {
		return c.Render("products", fiber.Map{}) // templates/products.html dosyasını render et
	})

	// API endpoint'lerini ekle
	app.Post("/api/product", handler.CreateProduct)
	app.Get("/api/products", handler.GetAllProduct)
	app.Delete("/api/product/:id", handler.DeleteProduct)

	// Server'ı başlat
	log.Fatal(app.Listen(":8080"))

	/*	dbClient := configs.GetCollection(configs.DB, "Products")

		ProductRepositoryDB := repository.NewProductRepositoryDB(dbClient)

		pr := app.ProductHandler{services.NewProductService(ProductRepositoryDB)}

		appRoute.Post("/api/product", pr.CreateProduct)
		appRoute.Get("/api/products", pr.GetAllProduct)
		appRoute.Delete("/api/product/:id", pr.DeleteProduct)
		appRoute.Listen(":8080") */

}
