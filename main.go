package main

import (
	"crypto/md5"
	"database/sql"
	"encoding/hex"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"strconv"

	_ "github.com/go-sql-driver/mysql"
)

var db *sql.DB

// Sepet veri yapısı
var cart = make(map[int]int) // {ProductID: Quantity}

// Kullanıcı yapısı
type User struct {
	ID       int
	Username string
	Role     string
}

// Ürün yapısı
type Product struct {
	ID          int
	Name        string
	Description string
	Price       float64
	ImageURL    string
	Quantity    int // Sepet için miktar alanı
}

// Veritabanı bağlantısını başlat
func initDB() {
	var err error
	dsn := "root@tcp(127.0.0.1:3306)/mywebsite"
	db, err = sql.Open("mysql", dsn)
	if err != nil {
		log.Fatal("Failed to connect to the database:", err)
	}

	if err = db.Ping(); err != nil {
		log.Fatal("Failed to ping the database:", err)
	}
}

// Şifreyi MD5 ile hashle
func hashPassword(password string) string {
	hash := md5.New()
	hash.Write([]byte(password))
	return hex.EncodeToString(hash.Sum(nil))
}

// Giriş sayfası handler
func loginPageHandler(w http.ResponseWriter, r *http.Request) {
	view, err := template.ParseFiles("templates/login.html")
	if err != nil {
		http.Error(w, "Error loading template", http.StatusInternalServerError)
		return
	}
	view.Execute(w, nil)
}

// Giriş işlemi handler
func loginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	username := r.FormValue("username")
	password := r.FormValue("password")
	hashedPassword := hashPassword(password)

	var storedPassword, role string
	var userID int
	err := db.QueryRow("SELECT id, password, role FROM users WHERE username = ?", username).Scan(&userID, &storedPassword, &role)
	if err != nil || storedPassword != hashedPassword {
		http.Error(w, "Invalid username or password", http.StatusUnauthorized)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:  "session_token",
		Value: fmt.Sprintf("%d", userID), // User ID'yi cookie'ye ekliyoruz
		Path:  "/",
	})
	http.Redirect(w, r, "/products", http.StatusSeeOther)
}

// Ürünler sayfası handler
func productPageHandler(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("session_token")
	if err != nil {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	// Giriş yapan kullanıcının ID'sini al
	_, err = strconv.Atoi(cookie.Value)
	if err != nil {
		http.Error(w, "Invalid session", http.StatusUnauthorized)
		return
	}

	// Veritabanından ürünleri getir
	rows, err := db.Query("SELECT id, name, description, price, image_url FROM products")
	if err != nil {
		http.Error(w, "Error fetching products", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var products []Product
	for rows.Next() {
		var product Product
		err := rows.Scan(&product.ID, &product.Name, &product.Description, &product.Price, &product.ImageURL)
		if err != nil {
			http.Error(w, "Error scanning product", http.StatusInternalServerError)
			return
		}
		products = append(products, product)
	}

	// Ürünler sayfasını render et
	view, err := template.ParseFiles("templates/products.html")
	if err != nil {
		http.Error(w, "Error loading template", http.StatusInternalServerError)
		return
	}

	view.Execute(w, products)
}

// Çıkış yapma handler
func logoutHandler(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:   "session_token",
		Value:  "",
		Path:   "/",
		MaxAge: -1,
	})
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// Sepete ürün ekle handler
func addToCartHandler(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("session_token")
	if err != nil {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	// Ürün ID'sini al
	productID, err := strconv.Atoi(r.URL.Query().Get("id"))
	if err != nil {
		http.Error(w, "Invalid product ID", http.StatusBadRequest)
		return
	}

	// Sepete ürünü ekle (varsa miktarı arttır)
	cart[productID]++

	// Sepet sayfasına yönlendir
	http.Redirect(w, r, "/cart", http.StatusSeeOther)
}

// Sepet sayfası handler
func cartPageHandler(w http.ResponseWriter, r *http.Request) {
	// Sepetteki ürünleri listele
	var cartProducts []Product
	for id, quantity := range cart {
		// Ürün ID'sine göre ürün bilgilerini al
		var product Product
		err := db.QueryRow("SELECT id, name, description, price, image_url FROM products WHERE id = ?", id).Scan(&product.ID, &product.Name, &product.Description, &product.Price, &product.ImageURL)
		if err != nil {
			http.Error(w, "Error fetching product details", http.StatusInternalServerError)
			return
		}
		// Sepet ürünlerini ve miktarını ekle
		product.Quantity = quantity
		cartProducts = append(cartProducts, product)
	}

	// Sepet sayfasını render et
	view, err := template.ParseFiles("templates/cart.html")
	if err != nil {
		http.Error(w, "Error loading template", http.StatusInternalServerError)
		return
	}

	view.Execute(w, cartProducts)
}

// Main fonksiyonu
func main() {
	initDB()
	defer db.Close()

	http.HandleFunc("/", loginPageHandler)
	http.HandleFunc("/login", loginHandler)
	http.HandleFunc("/products", productPageHandler)

	http.HandleFunc("/add-to-cart", addToCartHandler)
	http.HandleFunc("/cart", cartPageHandler)

	http.HandleFunc("/logout", logoutHandler)

	fmt.Println("Server running on http://localhost:8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
