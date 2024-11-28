package middleware

import (
    "a21hc3NpZ25tZW50/model"
    "net/http"

    "github.com/gin-gonic/gin"
    "github.com/golang-jwt/jwt"
)

func Auth() gin.HandlerFunc {
    return gin.HandlerFunc(func(ctx *gin.Context) {
        cookie, err := ctx.Cookie("session_token")
        if err != nil {
            if ctx.ContentType() == "application/json" {
                ctx.AbortWithStatus(http.StatusUnauthorized)
                return
            }
            ctx.Redirect(http.StatusSeeOther, "/user/login")
            ctx.Abort()
            return
        }

        token, err := jwt.Parse(cookie, func(t *jwt.Token) (interface{}, error) {
            return model.JwtKey, nil
        })

        if err != nil {
            if err == jwt.ErrSignatureInvalid {
                ctx.Status(http.StatusUnauthorized)
                return
            }
            ctx.Status(http.StatusBadRequest)
            return
        }

        if !token.Valid {
            ctx.Status(http.StatusBadRequest)
            return
        }

        claims, ok := token.Claims.(jwt.MapClaims)
        if !ok {
            ctx.Status(http.StatusBadRequest)
            return
        }

        email, ok := claims["email"].(string)
        if !ok {
            ctx.Status(http.StatusBadRequest)
            return
        }

        ctx.Set("email", email)

        ctx.Next()
    })
}
