package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log"
	"strconv"
	"time"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/gofiber/fiber/v2/middleware/logger"
	"github.com/gofiber/template/html/v2"
	"github.com/golang-jwt/jwt/v5"
	"sort"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/gridfs"
	"go.mongodb.org/mongo-driver/mongo/options"
)

///////////////////////////////////////////////////////////////////////////////
// 1) MongoDB Atlas Bağlantısı
///////////////////////////////////////////////////////////////////////////////

var mongoClient *mongo.Client

// Kolay erişim için fonksiyon (myWebsiteAPI DB):
func getCollection(collName string) *mongo.Collection {
	return mongoClient.Database("myWebsiteAPI").Collection(collName)
}

///////////////////////////////////////////////////////////////////////////////
// 2) Struct Tanımları
///////////////////////////////////////////////////////////////////////////////

type User struct {
	ID       primitive.ObjectID `json:"id" bson:"_id"`
	Username string             `json:"username" bson:"Username"`
	Password string             `json:"password" bson:"Password"`
	Role     string             `json:"role" bson:"Role"`
	// RandomID int               ` json:"random_id" bson:"RandomID" // Gerekirse
}

type Product struct {
	ID          primitive.ObjectID `json:"id" bson:"_id"`
	Name        string             `json:"name" bson:"name"`
	Description string             `json:"description" bson:"description"`
	Price       float64            `json:"price" bson:"price"`
	Quantity    int                `json:"quantity" bson:"quantity"`
	ImageURL    string             `json:"imageURL" bson:"imageURL"`
	SellerID    primitive.ObjectID `json:"sellerId" bson:"sellerId"`
}

type SellerProduct struct {
	ID          primitive.ObjectID `json:"id" bson:"_id"`
	Name        string             `json:"name" bson:"name"`
	Description string             `json:"description" bson:"description"`
	Price       float64            `json:"price" bson:"price"`
	Quantity    int                `json:"quantity" bson:"quantity"`
	ImageURL    string             `json:"imageURL" bson:"imageURL"`
	ProductID   primitive.ObjectID `json:"product_id" bson:"product_id"`
	UserID      primitive.ObjectID `json:"user_id" bson:"user_id"`
}

type Cart struct {
	Id        primitive.ObjectID `json:"id" bson:"_id,omitempty"`
	Username  string             `json:"username" bson:"Username"`
	Name      string             `json:"name" bson:"name,omitempty"`
	Price     float64            `json:"price" bson:"price,omitempty"`
	Quantity  int                `json:"quantity" bson:"quantity,omitempty"`
	ProductID primitive.ObjectID `json:"product_id" bson:"product_id"`
	UserID    primitive.ObjectID `json:"user_id" bson:"user_id"`
}

type Order struct {
	Id        primitive.ObjectID `json:"id" bson:"_id,omitempty"`
	Username  string             `json:"username" bson:"Username"`
	Name      string             `json:"name" bson:"name"`
	Price     float64            `json:"price" bson:"price"`
	Quantity  int                `json:"quantity" bson:"quantity"`
	ProductID primitive.ObjectID `json:"product_id" bson:"product_id"`
	UserID    primitive.ObjectID `json:"user_id" bson:"user_id"`
}

type SellerOrder struct {
	Id          primitive.ObjectID `json:"id" bson:"_id,omitempty"`
	Username    string             `json:"username" bson:"Username"`
	Name        string             `json:"name" bson:"name"`
	Description string             `json:"description" bson:"description"`
	Price       float64            `json:"price" bson:"price"`
	Quantity    int                `json:"quantity" bson:"quantity"`
	ProductID   primitive.ObjectID `json:"product_id" bson:"product_id"`
	UserID      primitive.ObjectID `json:"user_id" bson:"user_id"`
}

///////////////////////////////////////////////////////////////////////////////
// 3) JWT ve Middleware Fonksiyonları
///////////////////////////////////////////////////////////////////////////////

var jwtSecret = []byte("supersecretkey") // Örnek

// Basit cookie kontrolü
func AuthMiddleware(c *fiber.Ctx) error {
	log.Println(">>> [AuthMiddleware] Checking userID cookie")
	userID := c.Cookies("userID")
	if userID == "" {
		log.Println("    No userID cookie => Unauthorized")
		return c.Status(fiber.StatusUnauthorized).SendString("Unauthorized: no userID cookie")
	}
	log.Println("    userID cookie =", userID)
	return c.Next()
}

// İsteğe bağlı JWTMiddleware (kullanmak isterseniz)
func JWTMiddleware() fiber.Handler {
	return func(c *fiber.Ctx) error {
		tokenString := c.Get("Authorization")
		if tokenString == "" {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Missing token"})
		}
		// Bearer token
		tokenString = tokenString[7:]

		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method")
			}
			return jwtSecret, nil
		})

		if err != nil || !token.Valid {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Invalid token"})
		}

		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Invalid token claims"})
		}

		username, ok := claims["username"].(string)
		if !ok {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Invalid username in token"})
		}

		c.Locals("username", username)
		return c.Next()
	}
}

func registerHandler(c *fiber.Ctx) error {
	log.Println(">>> [registerHandler] => POST /register")

	// Gönderilen JSON verisini parse ediyoruz
	var body struct {
		Username string `json:"username"`
		Role     string `json:"role"`
		Password string `json:"password"`
	}
	if err := c.BodyParser(&body); err != nil {
		log.Println("    Body parse error:", err)
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid request format"})
	}

	// Aynı kullanıcı adı var mı kontrol edelim (isteğe bağlı)
	usersColl := getCollection("users")
	var existing User
	if err := usersColl.FindOne(context.TODO(), bson.M{"Username": body.Username}).Decode(&existing); err == nil {
		log.Println("    Username already exists")
		return c.Status(fiber.StatusConflict).JSON(fiber.Map{"error": "Username already exists"})
	}

	// Yeni kullanıcıyı oluşturup MongoDB’ye ekleyelim
	newUser := User{
		ID:       primitive.NewObjectID(),
		Username: body.Username,
		Password: body.Password, // Gerçek uygulamalarda şifreyi hashleyin!
		Role:     body.Role,
	}

	if _, err := usersColl.InsertOne(context.TODO(), newUser); err != nil {
		log.Println("    InsertOne error:", err)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to register user"})
	}

	log.Printf("    => User registered successfully: %s", newUser.Username)
	// Kayıt başarılı ise login sayfasına yönlendirelim
	return c.Redirect("/login")
}


///////////////////////////////////////////////////////////////////////////////
// 4) Handler Fonksiyonları (login, logout, addProduct, vb.)
//    => Her fonksiyonda benzer log ve kontrol yapısı
///////////////////////////////////////////////////////////////////////////////

// =========== LOGIN ============
func loginHandler(c *fiber.Ctx) error {
	log.Println(">>> [loginHandler] => POST /login")

	var body struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := c.BodyParser(&body); err != nil {
		log.Println("    Could not parse body:", err)
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid request format"})
	}
	log.Printf("    username=%s password=%s", body.Username, body.Password)

	// Önce sadece kullanıcı adına göre arama yapıyoruz.
	usersColl := getCollection("users")
	var user User
	if err := usersColl.FindOne(context.TODO(), bson.M{"Username": body.Username}).Decode(&user); err != nil {
		log.Println("    User not found:", err)
		// Kullanıcı bulunamadıysa, front-end'e özel hata mesajı dönüyoruz.
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "There is no such user, please REGISTER"})
	}

	/* bu kısım kalırsa nosql olmayabilir!!!
	// Kullanıcı bulunduysa, şifreyi kontrol ediyoruz.
	if user.Password != body.Password {
		log.Println("    Password mismatch for user:", body.Username)
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Invalid username or password"})
	}
		*/

	log.Printf("    FOUND => _id=%s, role=%s", user.ID.Hex(), user.Role)

	// Cookie set
	c.Cookie(&fiber.Cookie{
		Name:    "userID",
		Value:   user.ID.Hex(),
		Expires: time.Now().Add(24 * time.Hour),
	})
	c.Cookie(&fiber.Cookie{
		Name:    "Username",
		Value:   user.Username,
		Expires: time.Now().Add(24 * time.Hour),
	})

	log.Printf("    => Login success. userID cookie=%s (role=%s)", user.ID.Hex(), user.Role)

	// Yanıt: Rol bazlı yönlendirme
	if user.Role == "seller" {
		return c.JSON(fiber.Map{
			"role":        "seller",
			"redirectUrl": "/my-products",
			"message":     "Login successful (seller)",
		})
	}
	return c.JSON(fiber.Map{
		"role":        "user",
		"redirectUrl": "/products",
		"message":     "Login successful (user)",
	})
}


// =========== LOGOUT ============
func logoutHandler(c *fiber.Ctx) error {
	log.Println(">>> [logoutHandler] => POST /logout")

	// Cookie temizle
	c.Cookie(&fiber.Cookie{
		Name:     "userID",
		Value:    "",
		Expires:  time.Now().Add(-1 * time.Hour),
		HTTPOnly: true,
	})
	c.Cookie(&fiber.Cookie{
		Name:     "Username",
		Value:    "",
		Expires:  time.Now().Add(-1 * time.Hour),
		HTTPOnly: true,
	})
	log.Println("    Cookies cleared => redirect /")
	return c.Redirect("/")
}

// =========== ADD PRODUCT ============
func addProduct(c *fiber.Ctx) error {
	log.Println(">>> [addProduct] => POST /add-products")

	// Cookie'den userID al
	userID := c.Cookies("userID")
	if userID == "" {
		log.Println("    No userID => unauthorized")
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Unauthorized"})
	}

	// DB'de user bul
	oid, err := primitive.ObjectIDFromHex(userID)
	if err != nil {
		log.Println("    Invalid userID hex:", err)
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid userID hex"})
	}
	var user User
	if err := getCollection("users").FindOne(context.TODO(), bson.M{"_id": oid}).Decode(&user); err != nil {
		log.Println("    User not found:", err)
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "User not found"})
	}
	log.Printf("    => User found: %s (role=%s)", user.Username, user.Role)

	// Role seller mı?
	if user.Role != "seller" {
		log.Println("    Permission denied (user not seller).")
		return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "Permission denied"})
	}

	// Dosya var mı?
	var imageURL string
	file, fileErr := c.FormFile("image")
	if fileErr == nil {
		log.Println("    Found uploaded file =>", file.Filename)
		fileData, errOpen := file.Open()
		if errOpen != nil {
			log.Println("    file.Open error =>", errOpen)
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to open file"})
		}
		defer fileData.Close()

		bucket, errBucket := gridfs.NewBucket(mongoClient.Database("myWebsiteAPI"))
		if errBucket != nil {
			log.Println("    gridfs.NewBucket error =>", errBucket)
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Bucket error"})
		}

		uploadStream, errUpload := bucket.OpenUploadStream(file.Filename)
		if errUpload != nil {
			log.Println("    OpenUploadStream error =>", errUpload)
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Upload stream error"})
		}
		defer uploadStream.Close()

		if _, errCopy := io.Copy(uploadStream, fileData); errCopy != nil {
			log.Println("    copying file data error =>", errCopy)
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Copy file data error"})
		}
		imgID := uploadStream.FileID.(primitive.ObjectID)
		imageURL = "/file/" + imgID.Hex()
		log.Printf("    => Image stored in GridFS => %s", imageURL)
	} else {
		log.Println("    No image file found, skipping =>", fileErr)
		imageURL = ""
	}

	// Form field'lar
	name := c.FormValue("name")
	description := c.FormValue("description")
	priceStr := c.FormValue("price")
	qtyStr := c.FormValue("quantity")

	if name == "" || description == "" || priceStr == "" || qtyStr == "" {
		log.Println("    Missing form fields => name, desc, price, quantity required.")
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Missing required fields"})
	}

	priceVal, err := strconv.ParseFloat(priceStr, 64)
	if err != nil {
		log.Println("    Invalid price =>", err)
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid price"})
	}
	qtyVal, err := strconv.Atoi(qtyStr)
	if err != nil {
		log.Println("    Invalid quantity =>", err)
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid quantity"})
	}

	// Kaydet
	productID := primitive.NewObjectID()
	sellerProdColl := getCollection("seller-products")
	productsColl := getCollection("products")

	sellerDoc := SellerProduct{
		ID:          primitive.NewObjectID(),
		Name:        name,
		Description: description,
		Price:       priceVal,
		Quantity:    qtyVal,
		ImageURL:    imageURL,
		ProductID:   productID,
		UserID:      user.ID,
	}

	if _, err := sellerProdColl.InsertOne(context.TODO(), sellerDoc); err != nil {
		log.Println("    InsertOne(seller-products) error =>", err)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to insert seller-product"})
	}

	prodDoc := bson.M{
		"_id":         productID,
		"name":        name,
		"description": description,
		"price":       priceVal,
		"quantity":    qtyVal,
		"imageURL":    imageURL,
		"sellerId":    user.ID,
	}
	if _, err := productsColl.InsertOne(context.TODO(), prodDoc); err != nil {
		log.Println("    InsertOne(products) error =>", err)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to insert product"})
	}

	log.Printf("    => SUCCESS: product '%s' inserted for user '%s'", productID.Hex(), user.Username)
	return c.Redirect("/my-products")
}

// =========== GET MY PRODUCTS ============
func getMyProducts(c *fiber.Ctx) error {
	log.Println(">>> [getMyProducts] => GET /my-products")
	userID := c.Cookies("userID")
	if userID == "" {
		log.Println("    No userID => unauthorized")
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Unauthorized"})
	}

	uid, err := primitive.ObjectIDFromHex(userID)
	if err != nil {
		log.Println("    Invalid userID hex =>", err)
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid userID"})
	}

	filter := bson.M{"user_id": uid}
	cursor, err := getCollection("seller-products").Find(context.TODO(), filter)
	if err != nil {
		log.Println("    DB error =>", err)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "DB error"})
	}
	defer cursor.Close(context.TODO())

	var products []SellerProduct
	if err := cursor.All(context.TODO(), &products); err != nil {
		log.Println("    decode error =>", err)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Decode error"})
	}
	log.Printf("    => Found %d products for userID=%s", len(products), userID)

	return c.Render("my-products", fiber.Map{
		"SellerProducts": products,
	})
}

// =========== GET ALL PRODUCTS ============
func getProducts(c *fiber.Ctx) error {
    log.Println(">>> [getProducts] => GET /products")

    // 1) Cookie’den userID al
    userID := c.Cookies("userID")
    role := "guest" // default

    // 2) Eğer userID varsa, DB'den kullanıcıyı çekip role bul
    if userID != "" {
        oid, err := primitive.ObjectIDFromHex(userID)
        if err == nil {
            var user User
            errFind := getCollection("users").FindOne(context.TODO(), bson.M{"_id": oid}).Decode(&user)
            if errFind == nil {
                role = user.Role // "user" veya "seller"
            }
        }
    }

    // 3) Products'ları çek
    cursor, err := getCollection("products").Find(context.TODO(), bson.M{})
    if err != nil {
        log.Println("DB error =>", err)
        return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to fetch products"})
    }
    defer cursor.Close(context.TODO())

    var products []Product
    if err := cursor.All(context.TODO(), &products); err != nil {
        log.Println("decode error =>", err)
        return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to decode products"})
    }
    log.Printf("Found %d products total", len(products))

    // 4) Template’e render
    return c.Render("products", fiber.Map{
        "Products": products,
        "UserID":   userID,
        "UserRole": role,  // <-- ÖNEMLİ: Template’te $.UserRole ile kullanıyoruz
    })
}

// =========== GET FILE (GridFS) ============
func getFile(c *fiber.Ctx) error {
	log.Println(">>> [getFile] => GET /file/:id")
	fileIDHex := c.Params("id")
	fileID, err := primitive.ObjectIDFromHex(fileIDHex)
	if err != nil {
		log.Println("    Invalid fileID =>", fileIDHex)
		return c.Status(fiber.StatusBadRequest).SendString("Geçersiz dosya ID'si")
	}

	bucket, err := gridfs.NewBucket(mongoClient.Database("myWebsiteAPI"))
	if err != nil {
		log.Println("    Bucket error =>", err)
		return c.Status(fiber.StatusInternalServerError).SendString("GridFS bucket oluşturulamadı")
	}

	downloadStream, err := bucket.OpenDownloadStream(fileID)
	if err != nil {
		log.Println("    Dosya bulunamadı =>", err)
		return c.Status(fiber.StatusNotFound).SendString("Dosya bulunamadı")
	}
	defer downloadStream.Close()

	var buf bytes.Buffer
	if _, err := io.Copy(&buf, downloadStream); err != nil {
		log.Println("    Dosya okunurken hata =>", err)
		return c.Status(fiber.StatusInternalServerError).SendString("Dosya okunurken hata oluştu")
	}

	// Örnek: image/jpeg
	c.Type("jpeg")
	return c.Send(buf.Bytes())
}

///////////////////////////////////////////////////////////////////////////////
// 5) Sepet (Cart) ve Sipariş (Order) Fonksiyonları
///////////////////////////////////////////////////////////////////////////////

// =========== GET CART ITEMS ============
// getCart => Sepetteki ürünleri göster
func getCart(c *fiber.Ctx) error {
    // Basit mantık
    userID := c.Cookies("userID")
    if userID == "" {
        return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Unauthorized"})
    }
    uid, err := primitive.ObjectIDFromHex(userID)
    if err != nil {
        return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid userID"})
    }

    cursor, err := getCollection("carts").Find(context.TODO(), bson.M{"user_id": uid})
    if err != nil {
        return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "DB error"})
    }
    defer cursor.Close(context.TODO())

    var items []Cart
    if err := cursor.All(context.TODO(), &items); err != nil {
        return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Decode error"})
    }

    return c.Render("cart", fiber.Map{
        "CartItems": items,
    })
}

// Yardımcı fonksiyon
func getCartsFromDB(userID string) ([]Cart, error) {
	uid, err := primitive.ObjectIDFromHex(userID)
	if err != nil {
		return nil, fmt.Errorf("invalid userID hex => %v", err)
	}
	filter := bson.M{"user_id": uid}
	cursor, err := getCollection("carts").Find(context.TODO(), filter)
	if err != nil {
		return nil, fmt.Errorf("failed to find => %v", err)
	}
	defer cursor.Close(context.TODO())

	var carts []Cart
	if err := cursor.All(context.TODO(), &carts); err != nil {
		return nil, fmt.Errorf("decode error => %v", err)
	}
	return carts, nil
}

// =========== ADD TO CART ============
// addToCart => Kullanıcı sepete ürün ekler
// Formdan gelen "product_id", "name", "price", "quantity" vb. okuruz.
func addToCart(c *fiber.Ctx) error {
    log.Println(">>> [addToCart] => POST /add-to-cart")

    userID := c.Cookies("userID")
    if userID == "" {
        log.Println("    Unauthorized => no userID cookie")
        return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Unauthorized"})
    }

    productID := c.FormValue("product_id")
    name := c.FormValue("name")
    priceStr := c.FormValue("price")
    qtyStr := c.FormValue("quantity")

    // Parse
    oid, err := primitive.ObjectIDFromHex(productID)
    if err != nil {
        log.Println("    invalid product ID =>", err)
        return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid product ID"})
    }
    priceVal, err := strconv.ParseFloat(priceStr, 64)
    if err != nil {
        return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid price"})
    }
    qtyVal, err := strconv.Atoi(qtyStr)
    if err != nil {
        return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid quantity"})
    }

    uid, err := primitive.ObjectIDFromHex(userID)
    if err != nil {
        return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid user ID"})
    }

    // 1) Sepet (carts)
    cartsColl := getCollection("carts")
    filter := bson.M{"product_id": oid, "user_id": uid}
    var existing Cart
    errFind := cartsColl.FindOne(context.TODO(), filter).Decode(&existing)
    if errFind == nil {
        // varsa quantity + qtyVal
        update := bson.M{"$inc": bson.M{"quantity": qtyVal}}
        if _, errUpd := cartsColl.UpdateOne(context.TODO(), filter, update); errUpd != nil {
            return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to update cart"})
        }
        log.Printf("    => Updated existing cart item, +%d quantity\n", qtyVal)
    } else {
        // yoksa yeni ekle
        newCart := Cart{
            Id:        primitive.NewObjectID(),
            Username:  c.Cookies("Username"), // buyer username
            UserID:    uid,                   // buyer userID
            Quantity:  qtyVal,
            Name:      name,
            Price:     priceVal,
            ProductID: oid,
        }
        _, errIns := cartsColl.InsertOne(context.TODO(), newCart)
        if errIns != nil {
            return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to insert cart item"})
        }
        log.Println("    => Inserted new cart item")
    }

    // 2) orders (opsiyonel - user’ın tüm sipariş geçmişi)
    ordersColl := getCollection("orders")
    newOrder := Order{
        Id:        primitive.NewObjectID(),
        Username:  c.Cookies("Username"),  // buyer username
        Name:      name,
        Price:     priceVal,
        Quantity:  qtyVal,
        ProductID: oid,
        UserID:    uid, // buyer ID
    }
    _, errOrd := ordersColl.InsertOne(context.TODO(), newOrder)
    if errOrd != nil {
        log.Println("    InsertOne(orders) =>", errOrd)
        return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to add order"})
    }
    log.Println("    => Inserted new doc in 'orders'")

    // 3) seller-orders (kritik => satıcı my-orders aggregator görebilsin)
    sellerOrdersColl := getCollection("seller-orders")
    newSellerOrder := SellerOrder{
        Id:        primitive.NewObjectID(),
        Username:  c.Cookies("Username"), // buyer username
        Name:      name,
        Price:     priceVal,
        Quantity:  qtyVal,
        ProductID: oid,
        UserID:    uid, // buyer ID
        // Description vs. doldurabilirsiniz
    }
    _, errSo := sellerOrdersColl.InsertOne(context.TODO(), newSellerOrder)
    if errSo != nil {
        log.Println("    InsertOne(seller-orders) =>", errSo)
        return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to add seller order"})
    }
    log.Println("    => Inserted new doc in 'seller-orders'")

    // 4) Yönlendirme
    return c.Redirect("/carts")
}

// =========== REMOVE FROM CART ============
func removeFromCart(c *fiber.Ctx) error {
	log.Println(">>> [removeFromCart] => POST /remove-from-cart")
	// Bu örnekte form verisi "name" parametresi
	name := c.FormValue("name")
	if name == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Product name is required"})
	}

	username := c.Query("username") // ya da formValue("username")?
	if username == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "username is required"})
	}

	coll := getCollection("carts")
	filter := bson.M{"name": name}
	var existingCartItem Cart
	if err := coll.FindOne(context.TODO(), filter).Decode(&existingCartItem); err != nil {
		log.Println("    item not found =>", err)
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "Item not found in cart"})
	}

	if existingCartItem.Quantity > 1 {
		update := bson.M{"$inc": bson.M{"quantity": -1}}
		if _, err := coll.UpdateOne(context.TODO(), filter, update); err != nil {
			log.Println("    update error =>", err)
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to update cart item"})
		}
		log.Println("    => Decremented quantity by 1")
	} else {
		if _, err := coll.DeleteOne(context.TODO(), filter); err != nil {
			log.Println("    deleteOne error =>", err)
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to remove item from cart"})
		}
		log.Println("    => Removed item from cart (quantity was 1)")
	}

	// Ardından cart sayfasına dön
	return c.Redirect(fmt.Sprintf("/carts?username=%s", username))
}

///////////////////////////////////////////////////////////////////////////////
// 6) Sipariş Listeleri (Orders)
///////////////////////////////////////////////////////////////////////////////

// =========== GET ALL ORDERS ============
func getOrders(c *fiber.Ctx) error {
	log.Println(">>> [getOrders] => GET /orders")
	orders, err := getOrdersFromDB()
	if err != nil {
		log.Println("    DB error =>", err)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to fetch Orders"})
	}
	log.Printf("    => Found %d orders total", len(orders))

	return c.Render("order", fiber.Map{
		"Orders": orders,
	})
}

func getOrdersFromDB() ([]Order, error) {
	cursor, err := getCollection("orders").Find(context.TODO(), bson.M{})
	if err != nil {
		return nil, err
	}
	defer cursor.Close(context.TODO())

	var orders []Order
	if err := cursor.All(context.TODO(), &orders); err != nil {
		return nil, err
	}
	return orders, nil
}

// =========== GET SELLER ORDERS ============
func getSellerOrders(c *fiber.Ctx) error {
	log.Println(">>> [getSellerOrders] => GET /my-orders")
	sellerorders, err := getSellerOrderFromDB()
	if err != nil {
		log.Println("    DB error =>", err)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to fetch Seller Orders"})
	}
	log.Printf("    => Found %d seller-orders", len(sellerorders))

	return c.Render("seller-orders", fiber.Map{
		"SellerOrder": sellerorders,
	})
}

func getSellerOrderFromDB() ([]SellerOrder, error) {
	cursor, err := getCollection("seller-orders").Find(context.TODO(), bson.M{})
	if err != nil {
		return nil, err
	}
	defer cursor.Close(context.TODO())

	var sorders []SellerOrder
	if err := cursor.All(context.TODO(), &sorders); err != nil {
		return nil, err
	}
	return sorders, nil
}

// =========================================
// Aggregation için oluşturacağımız tipler:

// Bir ürünün alıcı bilgilerini toplamak için:
type BuyerInfo struct {
    Username    string  // alıcının kullanıcı adı
    Quantity    int     // bu üründen kaç adet sipariş verdi
    TotalPrice  float64 // bu üründen ne kadarlık sipariş verdi (Price * Quantity)
}

// Her ürünün özet bilgileri:
type AggregatedProduct struct {
    ProductName string      // ürün ismi
    TotalQty    int         // bu üründen toplam kaç adet sipariş edilmiş
    TotalPrice  float64     // bu ürünün toplam getirisi (Price * Quantity)
    Buyers      []BuyerInfo // kimler sipariş etmiş
}

// =========================================
// getMyOrders => satıcının siparişlerini toplu gösterir
func getMyOrders(c *fiber.Ctx) error {
    log.Println(">>> [getMyOrders] => GET /my-orders")

    // 1) Satıcı giriş yapmış mı, userID cookie al
    userID := c.Cookies("userID")
    if userID == "" {
        return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Unauthorized"})
    }
    sellerOID, err := primitive.ObjectIDFromHex(userID)
    if err != nil {
        return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid seller ID"})
    }

    // 2) seller-products koleksiyonundan bu satıcıya ait ürünleri çek
    //    Bu sayede hangi ProductID’ler bu satıcıya ait öğreniyoruz.
    sellerProductsColl := getCollection("seller-products")
    filter := bson.M{"user_id": sellerOID} // user_id = satıcı (owner)
    cursor, err := sellerProductsColl.Find(context.TODO(), filter)
    if err != nil {
        return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "DB error: find seller-products"})
    }
    defer cursor.Close(context.TODO())

    // 2b) Haritaya koy (productID -> ProductName)
    productMap := make(map[primitive.ObjectID]string)
    for cursor.Next(context.TODO()) {
        var sp SellerProduct
        if err := cursor.Decode(&sp); err == nil {
            productMap[sp.ProductID] = sp.Name
        }
    }

    // Eğer satıcının hiç ürünü yoksa
    if len(productMap) == 0 {
        log.Println("    => No seller-products found for this user => no orders")
        // Template’e gidelim ve "No Orders Found" gösterelim.
        return c.Render("seller-orders", fiber.Map{
            "AggregatedProducts": []AggregatedProduct{},
        })
    }

    // 3) seller-orders koleksiyonundan TÜM siparişleri çek
    //    (ya da isterseniz satıcıya ait ProductID bazında filtre yapabilirsiniz,
    //    ama basitçe hepsini alıp sonrasında eleriz.)
    sellerOrdersColl := getCollection("seller-orders")
    allCursor, err := sellerOrdersColl.Find(context.TODO(), bson.M{})
    if err != nil {
        return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "DB error: find seller-orders"})
    }
    defer allCursor.Close(context.TODO())

    var allOrders []SellerOrder
    if err := allCursor.All(context.TODO(), &allOrders); err != nil {
        return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Decode error: seller-orders"})
    }

    // 4) Artık, satıcıya ait ProductID’lere eşleşen order’ları gruplayacağız.
    //    => map[productID] => AggregatedProduct
    aggregator := make(map[primitive.ObjectID]*AggregatedProduct)

    for _, order := range allOrders {
        // order.ProductID satıcının productMap’inde var mı?
        prodName, ok := productMap[order.ProductID]
        if !ok {
            // Bu sipariş başka satıcıya ait ürün
            continue
        }

        // aggregator’da var mı?
        if aggregator[order.ProductID] == nil {
            aggregator[order.ProductID] = &AggregatedProduct{
                ProductName: prodName,
                Buyers:      []BuyerInfo{},
            }
        }
        ag := aggregator[order.ProductID]

        // Toplam qty, toplam price:
        ag.TotalQty += order.Quantity
        ag.TotalPrice += order.Price * float64(order.Quantity)

        // Buyer (kullanıcı) bul
        // - Aynı buyer birden çok sipariş verdiyse toplayalım.
        var found bool
        for i, buyer := range ag.Buyers {
            if buyer.Username == order.Username {
                // varsa qty +=, totalPrice +=
                ag.Buyers[i].Quantity += order.Quantity
                ag.Buyers[i].TotalPrice += (order.Price * float64(order.Quantity))
                found = true
                break
            }
        }
        // yoksa ekle
        if !found {
            ag.Buyers = append(ag.Buyers, BuyerInfo{
                Username:   order.Username,
                Quantity:   order.Quantity,
                TotalPrice: order.Price * float64(order.Quantity),
            })
        }
    }

    // 5) aggregator’ı slice’a dönüştürüp template’e yollayalım
    var result []AggregatedProduct
    for _, v := range aggregator {
        result = append(result, *v)
    }

    // (İsteğe bağlı) isim sırasına göre sort
    sort.Slice(result, func(i, j int) bool {
        return result[i].ProductName < result[j].ProductName
    })

    // 6) seller-orders.html’e render
    return c.Render("seller-orders", fiber.Map{
        "AggregatedProducts": result,
    })
}

///////////////////////////////////////////////////////////////////////////////
// 7) main() - Uygulamanın Giriş Noktası
///////////////////////////////////////////////////////////////////////////////
func main() {
	//---------------------------------------------------------------------------
	// 7.1) Mongo Atlas'a bağlan
	//---------------------------------------------------------------------------
	// Lütfen kendi URI'nizi girin:
	mongoURI := "mongodb+srv://me123:12345*@cluster0.76ktg.mongodb.net/myWebsiteAPI?retryWrites=true&w=majority"

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	clientOptions := options.Client().ApplyURI(mongoURI)
	var err error
	mongoClient, err = mongo.Connect(ctx, clientOptions)
	if err != nil {
		log.Fatal("MongoDB bağlantı hatası:", err)
	}
	if err := mongoClient.Ping(ctx, nil); err != nil {
		log.Fatal("MongoDB ping hatası:", err)
	}
	log.Println("✅ MongoDB Atlas bağlantısı başarılı.")

	//---------------------------------------------------------------------------
	// 7.2) Fiber uygulamasını başlat
	//---------------------------------------------------------------------------
	engine := html.New("./templates", ".html") // templates klasörü
	app := fiber.New(fiber.Config{
		Views: engine,
	})

	// Ortak middleware'ler
	app.Use(logger.New())
	app.Use(cors.New(cors.Config{
		AllowOrigins:     "http://127.0.0.1:5000",
		AllowCredentials: true,
	}))

	// Statik dosyalar
	app.Static("/", "templates")

	//---------------------------------------------------------------------------
	// 7.3) Rotalar
	//---------------------------------------------------------------------------
	// Giriş sayfası
	app.Get("/", func(c *fiber.Ctx) error {
		return c.Render("login", nil)
	})

	app.Get("/login", func(c *fiber.Ctx) error {
		return c.Render("login", nil)
	})

	app.Post("/login", loginHandler)


	app.Get("/register", func(c *fiber.Ctx) error {
		return c.Render("register", nil)
	})

	// Yeni kullanıcı kayıt POST isteğini karşılayan route
	app.Post("/register", registerHandler)
	// Login / Logout
	
	app.Post("/logout", logoutHandler)

	// Register sayfasını render eden GET rotası




	// Sepet örneği (zorunlu olmadan, login sonrası cookie kontrol edilsin)
	// Bu rotalardan önce AuthMiddleware ekliyoruz.
	// Yani login olmayan user /cart vs. göremesin.
	app.Use(AuthMiddleware)

//	app.Get("/cart", getCart)
//	app.Post("/add-to-cart", addToCart)
// bu asagısını ekledim
app.Post("/add-to-cart", AuthMiddleware, addToCart)
app.Get("/carts", AuthMiddleware, getCart)


	app.Post("/remove-from-cart", removeFromCart)

	// Ürün ekleme
	app.Get("/add-products", func(c *fiber.Ctx) error {
		return c.Render("add-products", nil)
	})
	app.Post("/add-products", addProduct)

	// Satıcının ürünleri
	app.Get("/my-products", getMyProducts)

	// Tüm ürünler
	app.Get("/products", getProducts)

	// Tüm orders
	app.Get("/orders", getOrders)
	// degistirdim...
	// app.Get("/my-orders", getSellerOrders)
	app.Get("/my-orders", getMyOrders)

	// GridFS ile dosya çekme
	app.Get("/file/:id", getFile)

	//---------------------------------------------------------------------------
	// 7.4) Uygulamayı Dinle
	//---------------------------------------------------------------------------
	log.Println("Server is running on http://127.0.0.1:5000")
	if err := app.Listen(":5000"); err != nil {
		log.Fatal(err)
	}
}