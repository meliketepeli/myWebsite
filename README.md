# 🛒 MyWebsite (Go + Fiber + MongoDB)

Bu proje, **Go (Golang)** kullanılarak geliştirilmiş basit bir **web uygulaması**dır.  
Backend tarafında **Fiber Framework** ve veritabanı olarak **MongoDB** kullanılmaktadır.  
Proje hem **JSON API** hem de **HTML Template Rendering** desteği sunmaktadır.

---

## 🚀 Özellikler
- 🔹 Fiber ile hızlı ve hafif web server
- 🔹 MongoDB üzerinden ürün yönetimi
- 🔹 API endpointleri ile JSON formatında veri sağlama
- 🔹 HTML template (views) üzerinden kullanıcıya ürünleri gösterme
- 🔹 Middleware: `logger` ve `cors` desteği

---

## 📂 Proje Yapısı
```bash
myWebsite/
│── main.go             # Ana uygulama dosyası
│── configs/            # MongoDB bağlantı ayarları
│── templates/          # HTML şablon dosyaları (login.html, products.html vb.)
│── go.mod              # Go modülleri
│── go.sum
```
## ⚙️ Kurulum & Çalıştırma
1. Reponun indirilmesi
```
git clone https://github.com/meliketepeli/myWebsite.git
cd myWebsite
```
2. Gerekli modüllerin indirilmesi
```
go mod tidy
```
3. MongoDB bağlantısının ayarlanması 
- configs klasöründe yer alan ayarları kendi MongoDB URI adresine göre güncelleyin.
- products isimli bir koleksiyon oluşturun.
- Örnek ürün verisi:
{
  "_id": "1",
  "name": "Laptop",
  "description": "Yüksek performanslı dizüstü bilgisayar",
  "price": 15000,
  "quantity": 10,
  "imageURL": "https://example.com/laptop.png"
}

4. Uygulamayı çalıştırma
```
go run main.go
```
5.Uygulama başarıyla başladığında:
Server is running on http://localhost:8080
