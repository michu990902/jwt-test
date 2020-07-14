package main

import (
	"os"
	"fmt"
	"log"
	"time"
	"html"
	"strings"
	"net/http"

	"golang.org/x/crypto/bcrypt"	
	env "github.com/joho/godotenv"
	"github.com/gin-gonic/gin"	
	"github.com/jinzhu/gorm"
	_ "github.com/jinzhu/gorm/dialects/mysql"
)

type Server struct {
	DB     *gorm.DB
	Router *gin.Engine
}

type User struct{
	ID                 uint64    `gorm:"primary_key;auto_increment" json:"id"`
	Nickname           string    `gorm:"size:50;not null;unique" json:"nickname" form:"nickname"`
	Email              string    `gorm:"size:100;not null;unique" json:"email" form:"email"`
	Password           string    `gorm:"size:60;not null;" json:"password" form:"password"`
	CreatedAt          time.Time `gorm:"default:CURRENT_TIMESTAMP" json:"created_at"`
	UpdatedAt          time.Time `gorm:"default:CURRENT_TIMESTAMP" json:"updated_at"`
}

func Hash(password string) ([]byte, error) {
	return bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
}

func VerifyPassword(hashedPassword, password string) error {
	return bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
}

func (u *User) BeforeSave() error {
	hashedPassword, err := Hash(u.Password)
	if err != nil {
		return err
	}
	u.Password = string(hashedPassword)
	return nil
}

func (u *User) Prepare() {
	u.ID = 0
	u.Nickname = html.EscapeString(strings.TrimSpace(u.Nickname))
	u.Email = html.EscapeString(strings.TrimSpace(u.Email))
	u.CreatedAt = time.Now()
	u.UpdatedAt = time.Now()
}

var server = Server{}

func main(){
	var err error
	err = env.Load()
	if err != nil {
		log.Fatalf("Error loading .env file: %v", err)
	}

	DbDriver := os.Getenv("DB_DRIV")
	DBURL := fmt.Sprintf("%s:%s@tcp(%s:%s)/%s?charset=utf8&parseTime=true", os.Getenv("DB_USER"), os.Getenv("DB_PASS"), os.Getenv("DB_HOST"), os.Getenv("DB_PORT"), os.Getenv("DB_NAME"))
	server.DB, err = gorm.Open(DbDriver, DBURL)
	if err != nil {
		log.Fatalf("Cannot connect to %s database", DbDriver)
	}
	server.DB.AutoMigrate(&User{})
	server.Router = gin.Default()

	server.Router.LoadHTMLGlob("templates/*")

	server.Router.GET("/", server.Home)
	server.Router.GET("/test", server.Test)
	server.Router.POST("/singin", server.SingIn)
	server.Router.GET("/singout", server.SingOut)

	server.Router.Run(":8080")
}

func (s *Server) Home(c *gin.Context){
	c.HTML(http.StatusOK, "index.gohtml", gin.H{
		"title": "Main website",
	})
}

func (s *Server) Test(c *gin.Context){
	c.HTML(http.StatusOK, "test.gohtml", gin.H{
		"title": "Test",
	})
}

func (s *Server) SingIn(c *gin.Context){

}

func (s *Server) SingOut(c *gin.Context){
	
}