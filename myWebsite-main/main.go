package main

import (
	"bytes"
	"context"
	"fmt"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/gofiber/fiber/v2/middleware/logger"
	"github.com/gofiber/template/html/v2"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo/gridfs"
	"io"
	"log"
	"newProject/configs"
	"strconv"
)

type Product struct {
	ID          string  `json:"id" bson:"_id"`
	Name        string  `json:"name" bson:"name"`
	Description string  `json:"description" bson:"description"`
	Price       float64 `json:"price" bson:"price"`
	Quantity    int     `json:"quantity" bson:"quantity"`
	ImageURL    string  `json:"imageURL" bson:"imageURL"`
}

type SellerProduct struct {
	ID          string  `json:"id" bson:"_id"`
	Name        string  `json:"name" bson:"name"`
	Description string  `json:"description" bson:"description"`
	Price       float64 `json:"price" bson:"price"`
	Quantity    int     `json:"quantity" bson:"quantity"`
	ImageURL    string  `json:"imageURL" bson:"imageURL"`
}

type User struct {
	Id       primitive.ObjectID `json:"id" bson:"_id"`
	Username string             `json:"username" bson:"Username"`
	Password string             `json:"password" bson:"Password"`
	Role     string             `json:"role" bson:"role"`
}

type Cart struct {
	Id       primitive.ObjectID `json:"id" bson:"_id,omitempty"`
	Username string             `json:"username" bson:"Username"`
	Name     string             `json:"name" bson:"name,omitempty"`
	Price    float32            `json:"price" bson:"price,omitempty"`
	Quantity int                `json:"quantity" bson:"quantity,omitempty"`

	// image url de olsa guzel olur ama image url sıkıntı biraz
}

type Order struct {
	Id       primitive.ObjectID `json:"id" bson:"_id,omitempty"`
	Username string             `json:"username" bson:"Username"`
	Name     string             `json:"name" bson:"name"`
	Price    float64            `json:"price" bson:"price"`
	Quantity int                `json:"quantity" bson:"quantity"`
}

type SellerOrder struct {
	Id          primitive.ObjectID `json:"id" bson:"_id,omitempty"`
	Username    string             `json:"username" bson:"Username"`
	Name        string             `json:"name" bson:"name"`
	Description string             `json:"description" bson:"description"`
	Price       float64            `json:"price" bson:"price"`
	Quantity    int                `json:"quantity" bson:"quantity"`

	//image url koymadım. Bunu bir düşün!
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

func getSellerProductsFromDB() ([]SellerProduct, error) {

	client := configs.DB
	collection := configs.GetCollection(client, "seller-products")

	cursor, err := collection.Find(nil, bson.M{})
	if err != nil {
		return nil, err
	}
	defer cursor.Close(context.TODO())

	var products []SellerProduct
	if err := cursor.All(context.TODO(), &products); err != nil {
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

func getOrdersFromDB() ([]Order, error) {

	client := configs.DB
	collection := configs.GetCollection(client, "orders")

	cursor, err := collection.Find(nil, bson.M{})
	if err != nil {
		return nil, err
	}
	defer cursor.Close(nil)

	var orders []Order
	if err := cursor.All(nil, &orders); err != nil {
		return nil, err
	}

	return orders, nil
}

func addToCart(c *fiber.Ctx) error {
	name := c.FormValue("name")
	priceStr := c.FormValue("price")
	quantityStr := c.FormValue("quantity")

	price, err := strconv.ParseFloat(priceStr, 32)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid price value"})
	}

	quantity, err := strconv.Atoi(quantityStr)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid quantity value"})
	}

	client := configs.DB
	collection := configs.GetCollection(client, "carts")

	var existingCartItem Cart
	err = collection.FindOne(nil, bson.M{"name": name}).Decode(&existingCartItem)

	if err == nil {
		update := bson.M{"$inc": bson.M{"quantity": quantity}}
		_, err = collection.UpdateOne(nil, bson.M{"name": name}, update)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to update cart item"})
		}
	} else {
		newCartItem := Cart{
			Id:       primitive.NewObjectID(),
			Name:     name,
			Price:    float32(price),
			Quantity: quantity,
		}
		_, err = collection.InsertOne(nil, newCartItem)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to add item to cart"})
		}
	}

	return c.Redirect("/carts")
}

func removeFromCart(c *fiber.Ctx) error {
	name := c.FormValue("name")
	if name == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Product name is required"})
	}

	client := configs.DB
	collection := configs.GetCollection(client, "carts")

	var existingCartItem Cart
	err := collection.FindOne(nil, bson.M{"name": name}).Decode(&existingCartItem)

	if err != nil {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "Item not found in cart"})
	}

	if existingCartItem.Quantity > 1 {
		update := bson.M{"$inc": bson.M{"quantity": -1}}
		_, err = collection.UpdateOne(nil, bson.M{"name": name}, update)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to update cart item"})
		}
	} else {
		// bir taneyse sil
		_, err = collection.DeleteOne(nil, bson.M{"name": name})
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to remove item from cart"})
		}
	}
	return c.Redirect("/carts")
}

func addProduct(c *fiber.Ctx) error {

	file, err := c.FormFile("image")
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "No file uploaded"})
	}

	fileData, err := file.Open()
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to read file"})
	}
	defer fileData.Close()

	client := configs.DB
	bucket, err := gridfs.NewBucket(client.Database("myWebsiteAPI"))
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to create GridFS bucket"})
	}

	uploadStream, err := bucket.OpenUploadStream(file.Filename)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to open upload stream"})
	}
	defer uploadStream.Close()

	if _, err := io.Copy(uploadStream, fileData); err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to copy file data"})
	}

	imageID := uploadStream.FileID.(primitive.ObjectID)
	imageURL := fmt.Sprintf("/file/%s", imageID.Hex())

	name := c.FormValue("name")
	description := c.FormValue("description")
	priceStr := c.FormValue("price")
	quantityStr := c.FormValue("quantity")

	price, err := strconv.ParseFloat(priceStr, 64)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid price value"})
	}

	quantity, err := strconv.Atoi(quantityStr)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid quantity value"})
	}

	product := SellerProduct{
		ID:          primitive.NewObjectID().Hex(),
		Name:        name,
		Description: description,
		Price:       price,
		Quantity:    quantity,
		ImageURL:    imageURL,
	}

	collection := configs.GetCollection(client, "seller-products")
	_, err = collection.InsertOne(c.Context(), product)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to add product to database"})
	}

	return c.Redirect("/my-products")
}

func logoutHandler(c *fiber.Ctx) error {

	return c.Redirect("/")
}

func getSellerOrderFromDB() ([]SellerOrder, error) {

	client := configs.DB
	collection := configs.GetCollection(client, "seller-orders")

	cursor, err := collection.Find(nil, bson.M{})
	if err != nil {
		return nil, err
	}
	defer cursor.Close(context.TODO())

	var sellerorders []SellerOrder
	if err := cursor.All(context.TODO(), &sellerorders); err != nil {
		return nil, err
	}
	return sellerorders, nil
}

func main() {

	engine := html.New("./templates", ".html")

	app := fiber.New(fiber.Config{
		Views: engine,
	})

	app.Use(logger.New())
	app.Use(cors.New())

	app.Get("/", func(c *fiber.Ctx) error {

		return c.Render("login", nil)

	})

	app.Get("/add-products", func(c *fiber.Ctx) error {

		return c.Render("add-products", nil)

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
		err := collection.FindOne(nil, bson.M{"Username": loginData.Username, "Password": loginData.Password}).Decode(&user)
		if err != nil {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Invalid username or password"})
		}

		if user.Role == "user" {
			return c.Redirect("/products")
		} else if user.Role == "seller" {
			return c.Redirect("/my-products")
		}

		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Unexpected role"})
	})

	app.Post("/logout", logoutHandler)

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

	app.Get("/my-products", func(c *fiber.Ctx) error {
		products, err := getSellerProductsFromDB()
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to fetch products"})
		}
		return c.Render("my-products", fiber.Map{"SellerProducts": products})
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

	// fonks olusturup gonderdim.
	app.Post("/add-to-cart", addToCart)

	app.Post("/remove-from-cart", removeFromCart)

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

	app.Get("/api/orders", func(c *fiber.Ctx) error {
		order, err := getOrdersFromDB()
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": "Failed to fetch ORDERS from the database",
			})
		}
		return c.JSON(order)
	})

	app.Get("/my-orders", func(c *fiber.Ctx) error {
		sellerorder, err := getSellerOrderFromDB()
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": "Failed to fetch Seller Orders from the database",
			})
		}
		return c.Render("seller-orders", fiber.Map{
			"SellerOrder": sellerorder,
		})
	})

	app.Post("/add-products", addProduct)

	app.Post("/upload", func(c *fiber.Ctx) error {
		file, err := c.FormFile("image")
		if err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "No file uploaded"})
		}

		fileData, err := file.Open()
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to read file"})
		}
		defer fileData.Close()

		client := configs.DB
		bucket, err := gridfs.NewBucket(client.Database("myWebsiteAPI"))
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to create GridFS bucket"})
		}

		uploadStream, err := bucket.OpenUploadStream(file.Filename)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to open upload stream"})
		}
		defer uploadStream.Close()

		if _, err := io.Copy(uploadStream, fileData); err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to copy file data"})
		}

		imageID := uploadStream.FileID.(primitive.ObjectID)
		imageURL := fmt.Sprintf("/file/%s", imageID.Hex())

		product := new(SellerProduct)
		if err := c.BodyParser(product); err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid product data"})
		}

		product.ImageURL = imageURL

		productsCollection := client.Database("myWebsiteAPI").Collection("seller-products")
		_, err = productsCollection.InsertOne(c.Context(), product)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to save product"})
		}

		return c.Redirect("/my-products")
	})

	app.Get("/file/:id", func(c *fiber.Ctx) error {
		id := c.Params("id")

		client := configs.DB
		collection := client.Database("myWebsiteAPI").Collection("images")

		objectID, err := primitive.ObjectIDFromHex(id)
		if err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid file ID"})
		}

		var result struct {
			FileName string `bson:"fileName"`
			Data     []byte `bson:"data"`
		}

		err = collection.FindOne(c.Context(), bson.M{"_id": objectID}).Decode(&result)
		if err != nil {
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "File not found"})
		}

		c.Set("Content-Type", "image/png") //jpeg de olabilir buna bir bak
		return c.SendStream(bytes.NewReader(result.Data), -1)
	})

	log.Println("Server is running on http://localhost:8080")
	err := app.Listen(":8080")
	if err != nil {
		log.Fatal(err)

	}

}
