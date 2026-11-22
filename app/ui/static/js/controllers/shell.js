document.addEventListener("alpine:init", () => {
  const NOTE_TITLE_MAX = 100;
  const NOTE_CONTENT_MAX = 5000;
  const WORKSPACE_NAME_MAX = 100;
  const CLIENT_NAME_MAX = 100;

  function workspaceSnapshot(raw) {
    if (!raw || typeof raw !== "object") return null;
    return {
      id: raw.id ?? null,
      name: raw.name || "",
      client_name: raw.client_name || "",
      status: raw.status || "",
    };
  }

  function labelFromWorkspace(workspace) {
    if (!workspace) return "";
    if (workspace.status !== "active") return "No active assessment";
    return workspace.name || "Workspace";
  }

  function hintFromWorkspace(workspace) {
    if (!workspace) return "";
    if (workspace.status !== "active") return "Templates stay available.";
    return workspace.client_name || "";
  }

  function emptyNoteDraft() {
    return { title: "", content: "" };
  }

  Alpine.data("shellPage", () => {
    const cached = workspaceSnapshot(pageCache.read("workspace"));
    return {
      workspace: cached,
      bootLabel: labelFromWorkspace(cached),
      bootHint: hintFromWorkspace(cached),
      error: "",
      loading: !cached,
      current: "",

      notesOpen: false,
      adminOpen: false,
      setupOpen: false,

      notes: [],
      notesMode: "list", // list | create | edit
      notesSelectedId: null,
      notesEditingId: null,
      notesDraft: emptyNoteDraft(),
      notesLoading: false,
      notesBusy: "",

      setupDraft: { name: "", clientName: "" },
      setupBusy: false,

      adminBusy: "",
      findingsCount: 0,
      templatesTotal: null,
      templatesLoaded: false,
      assetsTotal: (() => {
        const cached = pageCache.read("assets");
        if (!cached?.loaded) return null;
        const total = Number(cached.total);
        if (Number.isFinite(total)) return total;
        return Array.isArray(cached.items) ? cached.items.length : null;
      })(),
      assetsLoaded: Boolean(pageCache.read("assets")?.loaded),

      get isEmpty() {
        return !this.workspace || this.workspace.status !== "active";
      },

      get isActive() {
        return this.workspace?.status === "active";
      },

      get projectLabel() {
        return labelFromWorkspace(this.workspace) || this.bootLabel;
      },

      get identityHint() {
        return hintFromWorkspace(this.workspace) || this.bootHint;
      },

      get engagementLockTitle() {
        return "Needs an active assessment";
      },

      get findingsLockTitle() {
        if (this.isEmpty) return this.engagementLockTitle;
        if (this.assetsLoaded && this.assetsTotal === 0) {
          return "Add an asset first";
        }
        return "";
      },

      get findingsLocked() {
        return Boolean(this.findingsLockTitle);
      },

      get notesSelected() {
        return (
          this.notes.find((note) => note.id === this.notesSelectedId) || null
        );
      },

      get notesReaderShell() {
        return this.notesMode !== "list" || this.notes.length > 0;
      },

      get notesCanSave() {
        const title = this.notesDraft.title.trim();
        const content = this.notesDraft.content.trim();
        return (
          title.length > 0 &&
          content.length > 0 &&
          title.length <= NOTE_TITLE_MAX &&
          content.length <= NOTE_CONTENT_MAX &&
          !this.notesBusy
        );
      },

      get setupCanSubmit() {
        const name = this.setupDraft.name.trim();
        const client = this.setupDraft.clientName.trim();
        return (
          name.length >= 3 &&
          name.length <= WORKSPACE_NAME_MAX &&
          client.length >= 2 &&
          client.length <= CLIENT_NAME_MAX &&
          !this.setupBusy
        );
      },

      get adminResetIdle() {
        return !this.isActive;
      },

      get adminTemplatesBlocked() {
        return this.isActive && this.findingsCount > 0;
      },

      get adminTemplatesEmpty() {
        return this.templatesLoaded && this.templatesTotal === 0;
      },

      get adminTemplatesDisabled() {
        return (
          this.adminTemplatesBlocked ||
          !this.templatesLoaded ||
          this.adminTemplatesEmpty ||
          Boolean(this.adminBusy)
        );
      },

      get adminTemplatesDisableTitle() {
        if (this.adminTemplatesBlocked) {
          const n = this.findingsCount;
          return `Blocked while ${n} finding${n === 1 ? "" : "s"} remain`;
        }
        if (this.adminTemplatesEmpty) return "Template library is already empty";
        if (!this.templatesLoaded) return "Loading template library…";
        return "";
      },

      async init() {
        const match = location.pathname.match(
          /^\/workspace\/(templates|assets|findings)\/?$/
        );
        this.current = match ? match[1] : "templates";

        if (!(await session.ensureSession())) {
          location.replace("/");
          return;
        }

        try {
          const next = workspaceSnapshot(await api.get("/workspace"));
          if (next) {
            this.workspace = next;
            this.bootLabel = labelFromWorkspace(next);
            this.bootHint = hintFromWorkspace(next);
            pageCache.write("workspace", next);
          }
          if (
            this.isEmpty &&
            (this.current === "assets" || this.current === "findings")
          ) {
            location.replace("/workspace/templates");
            return;
          }
          if (this.isActive) {
            await this.loadAssetsMeta();
            if (this.assetsTotal === 0 && this.current === "findings") {
              location.replace("/workspace/assets");
              return;
            }
          } else {
            this.assetsTotal = 0;
            this.assetsLoaded = true;
          }
        } catch (err) {
          if (api.isAbortError(err)) return;
          this.error = err.message || "Could not load workspace";
        } finally {
          this.loading = false;
        }
      },

      async loadAssetsMeta() {
        try {
          const data = await api.get("/assets", {
            query: { skip: 0, limit: 1 },
            defaultErrorMessage: "Could not load assets",
          });
          const total = Number(data?.total);
          this.assetsTotal = Number.isFinite(total)
            ? total
            : Array.isArray(data?.assets)
              ? data.assets.length
              : 0;
        } catch (err) {
          if (api.isAbortError(err)) return;
          this.assetsTotal = 0;
        } finally {
          this.assetsLoaded = true;
        }
      },

      applyWorkspace(raw) {
        const next = workspaceSnapshot(raw);
        if (!next) return;
        this.workspace = next;
        this.bootLabel = labelFromWorkspace(next);
        this.bootHint = hintFromWorkspace(next);
        pageCache.write("workspace", next);
      },

      notePreview(note) {
        const text = String(note?.content || "")
          .replace(/\s+/g, " ")
          .trim();
        return text || "Empty note";
      },

      openNotes() {
        if (this.isEmpty || this.notesBusy) return;
        this.notesOpen = true;
        this.notesMode = "list";
        this.loadNotes();
      },

      closeNotes() {
        if (this.notesBusy) return;
        this.notesOpen = false;
        this.notesMode = "list";
        this.notesEditingId = null;
        this.notesDraft = emptyNoteDraft();
      },

      async loadNotes() {
        this.notesLoading = true;
        try {
          const data = await api.get("/notes", {
            defaultErrorMessage: "Could not load notes",
          });
          this.notes = Array.isArray(data?.notes) ? data.notes : [];
          if (!this.notesSelectedId && this.notes.length) {
            this.notesSelectedId = this.notes[0].id;
          } else if (
            this.notesSelectedId &&
            !this.notes.some((note) => note.id === this.notesSelectedId)
          ) {
            this.notesSelectedId = this.notes[0]?.id ?? null;
          }
        } catch (err) {
          if (api.isAbortError(err)) return;
          this.notes = [];
          const message = err.message || "Could not load notes";
          toast.show(message, { tone: "danger" });
        } finally {
          this.notesLoading = false;
        }
      },

      startNoteCreate() {
        this.notesEditingId = null;
        this.notesDraft = emptyNoteDraft();
        this.notesMode = "create";
        this.$nextTick(() => {
          document.getElementById("note-title")?.focus();
        });
      },

      startNoteEdit(note) {
        if (!note || this.notesBusy) return;
        this.notesEditingId = note.id;
        this.notesDraft = {
          title: note.title || "",
          content: note.content || "",
        };
        this.notesMode = "edit";
        this.$nextTick(() => {
          document.getElementById("note-title")?.focus();
        });
      },

      cancelNoteCompose() {
        if (this.notesBusy) return;
        this.notesEditingId = null;
        this.notesDraft = emptyNoteDraft();
        this.notesMode = "list";
      },

      async saveNote() {
        if (!this.notesCanSave) return;
        const title = this.notesDraft.title.trim();
        const content = this.notesDraft.content.trim();

        if (this.notesMode === "edit" && this.notesEditingId != null) {
          this.notesBusy = "edit";
          try {
            const updated = await api.patch(
              `/notes/${this.notesEditingId}`,
              { title, content },
              { defaultErrorMessage: "Could not update note" }
            );
            this.notes = this.notes.map((note) =>
              note.id === updated.id ? updated : note
            );
            this.notesSelectedId = updated.id;
            this.notesEditingId = null;
            this.notesMode = "list";
            this.notesDraft = emptyNoteDraft();
            toast.show("Note saved");
          } catch (err) {
            const message = err.message || "Could not update note";
            toast.show(message, { tone: "danger" });
          } finally {
            this.notesBusy = "";
          }
          return;
        }

        this.notesBusy = "create";
        try {
          const created = await api.post(
            "/notes/create",
            { title, content },
            { defaultErrorMessage: "Could not create note" }
          );
          this.notes = [created, ...this.notes];
          this.notesSelectedId = created.id;
          this.notesMode = "list";
          this.notesDraft = emptyNoteDraft();
          toast.show("Note created");
        } catch (err) {
          const message = err.message || "Could not create note";
          toast.show(message, { tone: "danger" });
        } finally {
          this.notesBusy = "";
        }
      },

      async deleteNote(note) {
        if (!note || this.notesBusy) return;
        const ok = await confirmDialog.ask({
          title: "Delete this note?",
          message: `“${note.title}” will be removed from this workspace. This can’t be undone.`,
          confirmLabel: "Delete note",
          action: async () => {
            this.notesBusy = "delete";
            try {
              await api.delete(`/notes/${note.id}`, {
                defaultErrorMessage: "Could not delete note",
              });
              this.notes = this.notes.filter((item) => item.id !== note.id);
              if (this.notesSelectedId === note.id) {
                this.notesSelectedId = this.notes[0]?.id ?? null;
              }
              toast.show("Note deleted");
            } catch (err) {
              const message = err.message || "Could not delete note";
              toast.show(message, { tone: "danger" });
              throw err;
            } finally {
              this.notesBusy = "";
            }
          },
        });
        if (!ok) return;
      },

      openSetup() {
        if (!this.isEmpty || this.setupBusy) return;
        this.setupOpen = true;
        this.setupDraft = { name: "", clientName: "" };
      },

      closeSetup() {
        if (this.setupBusy) return;
        this.setupOpen = false;
      },

      async submitSetup() {
        if (!this.setupCanSubmit) return;
        this.setupBusy = true;
        try {
          const data = await api.post(
            "/workspace/setup",
            {
              name: this.setupDraft.name.trim(),
              client_name: this.setupDraft.clientName.trim(),
            },
            { defaultErrorMessage: "Could not create assessment" }
          );
          this.applyWorkspace(data);
          pageCache.clear();
          pageCache.write("workspace", workspaceSnapshot(data));
          this.setupOpen = false;
          toast.queue("Assessment ready.");
          location.assign("/workspace/assets");
        } catch (err) {
          const message = err.message || "Could not create assessment";
          toast.show(message, { tone: "danger" });
          this.setupBusy = false;
        }
      },

      async openAdmin() {
        this.adminOpen = true;
        this.adminBusy = "";
        await this.refreshAdminStats();
      },

      closeAdmin() {
        if (this.adminBusy) return;
        this.adminOpen = false;
      },

      async refreshAdminStats() {
        this.templatesLoaded = false;
        if (this.isActive) {
          try {
            const stats = await api.get("/findings/stats", {
              defaultErrorMessage: "Could not load finding stats",
            });
            const bySeverity = stats?.by_severity || {};
            this.findingsCount = ["critical", "high", "medium", "low", "info"]
              .map((key) => Number(bySeverity[key]) || 0)
              .reduce((sum, n) => sum + n, 0);
          } catch {
            this.findingsCount = 0;
          }
        } else {
          this.findingsCount = 0;
        }

        try {
          const data = await api.get("/templates", {
            query: { skip: 0, limit: 1 },
            defaultErrorMessage: "Could not load templates",
          });
          this.templatesTotal = Number(data?.total);
          if (!Number.isFinite(this.templatesTotal)) {
            this.templatesTotal = Array.isArray(data?.templates)
              ? data.templates.length
              : 0;
          }
        } catch (err) {
          if (api.isAbortError(err)) return;
          this.templatesTotal = 0;
          toast.show(err.message || "Could not load templates", {
            tone: "danger",
          });
        } finally {
          this.templatesLoaded = true;
        }
      },

      async resetWorkspace() {
        if (this.adminResetIdle || this.adminBusy) return;
        const ok = await confirmDialog.ask({
          title: "Reset this workspace?",
          message:
            "All findings, assets, and notes in the active workspace will be permanently deleted. The global template library is preserved.",
          confirmLabel: "Reset workspace",
          action: async () => {
            this.adminBusy = "reset";
            try {
              await api.delete("/admin/workspace/reset", {
                defaultErrorMessage: "Could not reset the workspace",
              });
              pageCache.clear();
              this.adminOpen = false;
              toast.queue("Workspace reset. Audit data purged.");
              location.assign("/workspace/templates");
            } catch (err) {
              const message = err.message || "Could not reset the workspace";
              toast.show(message, { tone: "danger" });
              this.adminBusy = "";
              throw err;
            }
          },
        });
        if (!ok) return;
      },

      async clearTemplates() {
        if (this.adminTemplatesDisabled) return;
        const ok = await confirmDialog.ask({
          title: "Clear the template library?",
          message:
            "Every template will be permanently deleted. This fails if any active finding still references a template.",
          confirmLabel: "Clear templates",
          action: async () => {
            this.adminBusy = "templates";
            try {
              await api.delete("/admin/templates", {
                defaultErrorMessage: "Could not clear the template library",
              });
              pageCache.write("templates", {
                loaded: true,
                items: [],
                total: 0,
              });
              this.templatesTotal = 0;
              this.adminOpen = false;
              this.adminBusy = "";
              if (this.current === "templates") {
                toast.queue("Template library cleared.");
                location.reload();
              } else {
                toast.show("Template library cleared.");
              }
            } catch (err) {
              const message =
                err.message || "Could not clear the template library";
              toast.show(message, { tone: "danger" });
              this.adminBusy = "";
              throw err;
            }
          },
        });
        if (!ok) return;
      },

      logout() {
        session.logout();
        location.assign("/");
      },
    };
  });
});
