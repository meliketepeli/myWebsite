package main

import (
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/gofiber/fiber/v2/middleware/logger"
	"github.com/gofiber/template/html/v2"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"log"
	"newProject/configs"
)

type Product struct {
	ID          string  `json:"id" bson:"_id"`
	Name        string  `json:"name" bson:"name"`
	Description string  `json:"description" bson:"description"`
	Price       float64 `json:"price" bson:"price"`
	Quantity    int     `json:"quantity" bson:"quantity"`
	ImageURL    string  `json:"imageURL" bson:"imageURL"`
}

type User struct {
	Id       primitive.ObjectID `json:"id" bson:"_id"`
	Username string             `json:"username" bson:"username"`
	Password string             `json:"Password" bson:"Password"`
	Role     string             `json:"role" bson:"role"`
}

type Cart struct {
	Id       primitive.ObjectID `bson:"_id,omitempty"`
	Name     string             `bson:"name,omitempty"`
	Price    float32            `bson:"price,omitempty"`
	Quantity int                `bson:"quantity,omitempty"`

	// image url de olsa guzel olur
}

type Orders struct {
	Id       primitive.ObjectID ` bson:"_id,omitempty"`
	Name     string             `bson:"name"`
	Price    float64            ` bson:"price"`
	Quantity int                ` bson:"quantity"`
}

func getProductsFromDB() ([]Product, error) {

	client := configs.DB
	collection := configs.GetCollection(client, "products")

	cursor, err := collection.Find(nil, bson.M{})
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

func getUsersFromDB() ([]User, error) {

	client := configs.DB
	collection := configs.GetCollection(client, "users")

	cursor, err := collection.Find(nil, bson.M{})
	if err != nil {
		log.Println("Error fetching users:", err)
		return nil, err
	}
	defer cursor.Close(nil)

	var users []User
	if err := cursor.All(nil, &users); err != nil {

		log.Println("Error decoding users:", err)

		return nil, err
	}

	log.Println("Fetched users:", users)
	return users, nil
}

func getCartsFromDB() ([]Cart, error) {

	client := configs.DB
	collection := configs.GetCollection(client, "carts")

	cursor, err := collection.Find(nil, bson.M{})
	if err != nil {
		return nil, err
	}
	defer cursor.Close(nil)

	var carts []Cart
	if err := cursor.All(nil, &carts); err != nil {
		return nil, err
	}

	return carts, nil
}

func getOrdersFromDB() ([]Orders, error) {

	client := configs.DB
	collection := configs.GetCollection(client, "orders")

	cursor, err := collection.Find(nil, bson.M{})
	if err != nil {
		return nil, err
	}
	defer cursor.Close(nil)

	var orders []Orders
	if err := cursor.All(nil, &orders); err != nil {
		return nil, err
	}

	return orders, nil
}

func main() {

	engine := html.New("./templates", ".html")
	engine.Reload(true)

	app := fiber.New(fiber.Config{
		Views: engine,
	})

	app.Use(logger.New())
	app.Use(cors.New())

	app.Get("/", func(c *fiber.Ctx) error {

		return c.Render("login", nil)

	})

	app.Post("/login", func(c *fiber.Ctx) error {
		var loginData struct {
			Username string `json:"username"`
			Password string `json:"password"`
		}

		if err := c.BodyParser(&loginData); err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid request"})
		}
		client := configs.DB
		collection := configs.GetCollection(client, "users")

		var user User
		err := collection.FindOne(nil, bson.M{"username": loginData.Username, "Password": loginData.Password}).Decode(&user)
		if err != nil {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Invalid username or password"})
		}

		if user.Role == "user" {
			return c.Redirect("/products")
		} else if user.Role == "seller" {
			return c.Redirect("/admin") // burasına bak
		}

		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Unexpected role"})
	})

	app.Get("/api/products", func(c *fiber.Ctx) error {
		products, err := getProductsFromDB()
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": "Failed to fetch products from the database",
			})
		}
		return c.JSON(products)
	})

	app.Get("/products", func(c *fiber.Ctx) error {
		products, err := getProductsFromDB()
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": "Failed to fetch products from the database",
			})
		}
		return c.Render("products", fiber.Map{
			"Products": products,
		})
	})

	app.Get("/api/users", func(c *fiber.Ctx) error {
		user, err := getUsersFromDB()
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": "Failed to fetch USERS from the database",
			})
		}
		return c.JSON(user)
	})

	app.Get("/users", func(c *fiber.Ctx) error {
		user, err := getUsersFromDB()
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": "Failed to fetch Users from the database",
			})
		}
		return c.Render("user", fiber.Map{
			"Users": user,
		})
	})

	app.Get("/api/carts", func(c *fiber.Ctx) error {
		cart, err := getCartsFromDB()
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": "Failed to fetch CARTS from the database",
			})
		}
		return c.JSON(cart)
	})

	app.Get("/carts", func(c *fiber.Ctx) error {
		cart, err := getCartsFromDB()
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": "Failed to fetch Carts from the database",
			})
		}
		return c.Render("cart", fiber.Map{
			"Carts": cart,
		})
	})

	app.Get("/api/carts", func(c *fiber.Ctx) error {
		cart, err := getCartsFromDB()
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": "Failed to fetch CARTS from the database",
			})
		}
		return c.JSON(cart)
	})

	app.Get("/orders", func(c *fiber.Ctx) error {
		order, err := getOrdersFromDB()
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": "Failed to fetch Orders from the database",
			})
		}
		return c.Render("order", fiber.Map{
			"Orders": order,
		})
	})

	log.Println("Server is running on http://localhost:8080")
	err := app.Listen(":8080")
	if err != nil {
		log.Fatal(err)
	}
}
