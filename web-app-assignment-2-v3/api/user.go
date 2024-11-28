package api

import (
	"a21hc3NpZ25tZW50/model"
	"a21hc3NpZ25tZW50/service"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt"
)

type UserAPI interface {
	Register(c *gin.Context)
	Login(c *gin.Context)
	GetUserTaskCategory(c *gin.Context)
}

type userAPI struct {
	userService service.UserService
}

func NewUserAPI(userService service.UserService) *userAPI {
	return &userAPI{userService}
}

func (u *userAPI) Register(c *gin.Context) {
	var user model.UserRegister

	if err := c.BindJSON(&user); err != nil {
		c.JSON(http.StatusBadRequest, model.NewErrorResponse("invalid decode json"))
		return
	}

	if user.Email == "" || user.Password == "" || user.Fullname == "" {
		c.JSON(http.StatusBadRequest, model.NewErrorResponse("register data is empty"))
		return
	}

	var recordUser = model.User{
		Fullname: user.Fullname,
		Email:    user.Email,
		Password: user.Password,
	}

	recordUser, err := u.userService.Register(&recordUser)
	if err != nil {
		c.JSON(http.StatusInternalServerError, model.NewErrorResponse(err.Error()))
		return
	}

	c.JSON(http.StatusCreated, model.NewSuccessResponse("register success"))
}

func (u *userAPI) Login(c *gin.Context) {
	var loginData model.UserLogin

	if err := c.BindJSON(&loginData); err != nil {
		c.JSON(http.StatusBadRequest, model.NewErrorResponse("invalid decode json"))
		return
	}

	if loginData.Email == "" || loginData.Password == "" {
		c.JSON(http.StatusBadRequest, model.NewErrorResponse("email or password is empty"))
		return
	}

	var userModel = model.User{
		Email:    loginData.Email,
		Password: loginData.Password,
	}

	tokenStr, err := u.userService.Login(&userModel)
	if err != nil {
		if strings.Contains(err.Error(), "invalid credentials") {
			c.JSON(http.StatusUnauthorized, model.NewErrorResponse("invalid credentials"))
		} else {
			c.JSON(http.StatusInternalServerError, model.NewErrorResponse("error internal server"))
		}
		return
	}

	c.SetCookie("session_token", *tokenStr, 3600, "/", "", false, true)

	var claim model.Claims
	token, err := jwt.ParseWithClaims(*tokenStr, &claim, func(t *jwt.Token) (interface{}, error) {
		return model.JwtKey, nil
	})
	if err != nil {
		c.JSON(http.StatusInternalServerError, model.NewErrorResponse("could not generate token"))
		return
	}

	if !token.Valid {
		c.JSON(http.StatusBadRequest, model.NewErrorResponse("Token not valid"))
	}

	c.JSON(http.StatusOK, model.NewSuccessResponse("login success"))
}

func (u *userAPI) GetUserTaskCategory(c *gin.Context) {
	tasks, err := u.userService.GetUserTaskCategory()
	if err != nil {
		c.JSON(http.StatusInternalServerError, model.NewErrorResponse("could not retrieve tasks"))
		return
	}

	c.JSON(http.StatusOK, tasks)
}
