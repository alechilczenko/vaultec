document.addEventListener("alpine:init", () => {
  Alpine.data("loginPage", () => ({
    username: "",
    password: "",
    error: "",
    loading: false,

    async init() {
      if (session.isAuthenticated()) {
        location.replace("/workspace/templates");
      }
    },

    async submit() {
      if (!this.username || !this.password) return;
      this.loading = true;
      this.error = "";
      try {
        await session.login(this.username, this.password);
        let destination = "/workspace/templates";
        try {
          const workspace = await api.get("/workspace");
          if (workspace.status === "active") destination = "/workspace/findings";
        } catch {
          // Templates are always reachable after auth; assessment setup is optional.
        }
        location.assign(destination);
      } catch (err) {
        this.error = err.message || "Username or password is incorrect.";
        this.loading = false;
      }
    },
  }));
});
