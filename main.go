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

	
	// jwt "github.com/dgrijalva/jwt-go"
	// "github.com/gorilla/sessions"
	"github.com/wader/gormstore"
)

type Server struct {
	DB     *gorm.DB
	Router *gin.Engine
	Store  *gormstore.Store
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

func (s *Server) CreateUser(nickname, email, password string){
	u := User{
		Nickname: nickname,
		Email: email,
		Password: password,
	}
	u.BeforeSave()
	u.Prepare()
	err := s.DB.Create(&u).Error
	fmt.Println(err)
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


	//
	server.Store = gormstore.New(server.DB, []byte(os.Getenv("API_SECRET")))
	// db cleanup every hour
	// close quit channel to stop cleanup
	quit := make(chan struct{})
	go server.Store.PeriodicCleanup(1*time.Hour, quit)
	//

	//
	server.CreateUser("test1", "test@test.pl", "1234")
	server.CreateUser("test2", "test2@test.pl", "zaq1@WSX")
	//

	server.Router.LoadHTMLGlob("templates/*")

	server.Router.GET("/", server.Home)
	// server.Router.GET("/test", server.Test)
	// server.Router.GET("/test", server.isLoggedIn(server.Test))
	
	server.Router.POST("/singin", server.SingIn)
	server.Router.GET("/singout", server.SingOut)

	authorized := server.Router.Group("/")

	authorized.Use(isLoggedIn())
	{
		authorized.GET("/test", server.Test)
	}

	server.Router.Run(":8080")
}

func (s *Server) Home(c *gin.Context){
	//
	// s.AddUserToStore(c, 1)
	//
	c.HTML(http.StatusOK, "index.gohtml", gin.H{
		"title": "Main website",
	})
}

func (s *Server) Test(c *gin.Context){
	//
	s.GetUserFromStore(c)
	//
	c.HTML(http.StatusOK, "test.gohtml", gin.H{
		"title": "Test",
	})
}

func (s *Server) SingIn(c *gin.Context){
	var tmpUser, user User
	var err error

	err = c.ShouldBindJSON(&tmpUser)
	if err != nil {
		c.JSON(http.StatusUnprocessableEntity, gin.H{
			"message": err.Error(),
		})
		return
	}

	//auth
	err = s.DB.Where("email = ?", tmpUser.Email).First(&user).Error
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"message": err.Error(),
		})
		return
	}

	err = VerifyPassword(user.Password, tmpUser.Password)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{
			"message": err.Error(),
		})
		return
	}

	// token, err := CreateToken(user.ID)
	// if err != nil {
	//    	c.JSON(http.StatusUnprocessableEntity, gin.H{
	// 		"message": err.Error(),
	// 	})
	//    return
	// }
	// c.Redirect(http.StatusOK, "/")
	c.JSON(http.StatusOK, gin.H{
		"message": "Login succesfull",
	})
}

func (s *Server) SingOut(c *gin.Context){
	
	c.Redirect(http.StatusOK, "/")
}

func (s *Server) AddUserToStore(c *gin.Context, userID uint64){
	session, err := s.Store.Get(c.Request, "mind-map-session")
	if err != nil {
		fmt.Println("store error:", err.Error())
		//json internal server error
		return
	}
	session.Values["user_id"] = userID
	session.Values["user_role"] = "admin" 
	//termin wygasania sesji
	session.Values["exp"] = time.Now().Add(time.Hour * 1).Unix()
	s.Store.Save(c.Request, c.Writer, session)
}

func (s *Server) GetUserFromStore(c *gin.Context){
	session, err := s.Store.Get(c.Request, "mind-map-session")
	if err != nil {
		fmt.Println("store error:", err.Error())
		//json internal server error
		return
	}
	userID := session.Values["user_id"].(uint64)
	userRole := session.Values["user_role"].(string)
	fmt.Println("logged user:", userID, "(", userRole, ")")
}


func isLoggedIn() gin.HandlerFunc {	
	return func (c *gin.Context){
		_, err := c.Cookie("mind-map-session")
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"message": "Unauthorized",
			})
			return
		}
		c.Next()
	}

	// session, err := s.Store.Get(c.Request, "session")
	// if err != nil {
	// 	c.JSON(http.StatusInternalServerError, gin.H{
	// 		"message": err.Error(),
	// 	})
	// 	return
	// }

	// userID := session.Values["user_id"].(uint64)
	// userRole := session.Values["role"].(string)
	
	// license := session.Values["license_type"].(bool)
	//!!!licencja z bazy


}