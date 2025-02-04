package main

import (
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/gofiber/fiber/v2/middleware/logger"
	"github.com/gofiber/template/html/v2"
	"go.mongodb.org/mongo-driver/bson"

	"log"
	"newProject/configs" // configs paketini import ediyoruz
)

// Ürün yapısı
type Product struct {
	ID          string  `json:"id" bson:"_id"`
	Name        string  `json:"name" bson:"name"`
	Description string  `json:"description" bson:"description"`
	Price       float64 `json:"price" bson:"price"`
	Quantity    int     `json:"quantity" bson:"quantity"`
	ImageURL    string  `json:"imageURL" bson:"imageURL"`
}

// MongoDB'den ürünleri al
func getProductsFromDB() ([]Product, error) {
	// MongoDB client'ını al
	client := configs.DB
	// MongoDB koleksiyonunu al
	collection := configs.GetCollection(client, "products") // "products" koleksiyonunu kullanıyoruz

	// Ürünleri MongoDB'den çek
	cursor, err := collection.Find(nil, bson.M{}) // Tüm ürünleri getir
	if err != nil {
		return nil, err
	}
	defer cursor.Close(nil)

	var products []Product
	if err := cursor.All(nil, &products); err != nil {
		return nil, err
	}

	return products, nil
}

func main() {
	// HTML template motoru başlatma
	engine := html.New("./templates", ".html")

	// Fiber uygulaması başlatma
	app := fiber.New(fiber.Config{
		Views: engine, // Views ile template motorunu tanımlıyoruz
	})

	// Middleware (Logger ve CORS)
	app.Use(logger.New())
	app.Use(cors.New())

	// Ana sayfa route'ı
	app.Get("/", func(c *fiber.Ctx) error {
		return c.Render("login", nil) // login.html dosyasını render et
	})

	// /api/products route'ı - MongoDB'den JSON formatında ürünler döndürür
	app.Get("/api/products", func(c *fiber.Ctx) error {
		products, err := getProductsFromDB()
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": "Failed to fetch products from the database",
			})
		}
		return c.JSON(products)
	})

	// /products route'ı - MongoDB'den ürünleri HTML şablonunda render eder
	app.Get("/products", func(c *fiber.Ctx) error {
		products, err := getProductsFromDB()
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": "Failed to fetch products from the database",
			})
		}
		return c.Render("products", fiber.Map{
			"Products": products, // Ürünleri şablona aktarıyoruz
		})
	})

	// Server'ı başlat
	log.Println("Server is running on http://localhost:8080")
	err := app.Listen(":8080")
	if err != nil {
		log.Fatal(err)
	}
}
