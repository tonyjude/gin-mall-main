package middleware

import (
	"fmt"
	"github.com/CocaineCong/gin-mall/pkg/e"
	"github.com/casbin/casbin"
	"github.com/gin-gonic/gin"
	"net/http"
	"os"
)

func Authorize() gin.HandlerFunc {
	return func(c *gin.Context) {
		p := c.Request.URL.Path
		m := c.Request.Method
		var code int
		code = e.SUCCESS
		role := "superAdmin" //根据userid通过redis获取
		ok, err := enforce(role, p, m)
		if err != nil {
			c.JSON(http.StatusForbidden, gin.H{
				"status": code,
				"msg":    e.GetMsg(code),
				"data":   "未授权",
			})
			c.Abort()
			return
		}

		if !ok {
			c.JSON(http.StatusUnauthorized, gin.H{
				"status": code,
				"msg":    e.GetMsg(code),
				"data":   "未授权",
			})
			c.Abort()
			return
		}
		c.Next()
	}
}

func enforce(sub string, obj string, act string) (bool, error) {
	dir, _ := os.Getwd()
	modelPath := dir + "/config/locales/rbac_model.conf"
	csvPath := dir + "/config/locales/rbac2.csv"
	enforcer := casbin.NewEnforcer(modelPath, csvPath)
	err := enforcer.LoadPolicy()
	if err != nil {
		return false, fmt.Errorf("failed to load policy from csv: %w", err)
	}
	ok := enforcer.Enforce(sub, obj, act)
	return ok, nil
}
