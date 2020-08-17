<template>
  <h1>登录成功跳转首页</h1>
</template>

<script>
import {setLoginedUser} from "@/http/axios";
export default {
  mounted() {
    setLoginedUser("github", this.$route.query.token);
    this.$message({
      message: "登录成功",
      type: "success",
    });
    this.$router.push("/home");
  },
};
</script>

<style>
</style>