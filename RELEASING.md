# Releasing

Versioning is `MAJOR.MINOR.PATCH`. **Bump the patch on every deploy**, so the
version reported by `/healthz` always identifies exactly what is running.

The version lives in two places, which must agree:

- `src/loseit_mcp/__init__.py` — `__version__`, what `/healthz` reports
- `pyproject.toml` — `version`

## Steps

1. **Bump the version** in both files.

2. **Verify.**

   ```console
   uv run ruff check src tests
   uv run pytest
   ```

3. **Commit and tag.** The tag is what makes a deployed commit hash meaningful
   later.

   ```console
   git commit -am "..."
   git tag -a v0.3.7 -m "Describe what changed"
   git push origin main --follow-tags
   ```

4. **Build with the stamp.** These arguments are what `/healthz` reports; an
   unstamped image says `unknown`, which is a signal in itself.

   ```console
   docker build \
     --build-arg BUILD_COMMIT=$(git rev-parse --short HEAD) \
     --build-arg BUILD_TIME=$(date -u +%Y-%m-%dT%H:%M:%SZ) \
     --build-arg BUILD_TAG=v0.3.7 \
     -t <registry>.azurecr.io/loseit-mcp:v0.3.7 .

   docker push <registry>.azurecr.io/loseit-mcp:v0.3.7
   ```

   Build locally rather than with `az acr build` — ACR's classic agent has no
   BuildKit, and the Dockerfile's cache mounts need it.

   Roll the image tag rather than reusing `:latest`. It makes the deployed
   build unambiguous and lets you roll back by pointing at the previous tag.

5. **Deploy.**

   ```console
   az webapp config container set \
     --resource-group <rg> --name <app-name> \
     --container-image-name <registry>.azurecr.io/loseit-mcp:v0.3.7 \
     --container-registry-url https://<registry>.azurecr.io
   az webapp restart --resource-group <rg> --name <app-name>
   ```

6. **Confirm what landed.** Do not assume the restart picked up the new image —
   check.

   ```console
   curl https://<host>/healthz
   ```

   The reported `version`, `commit`, and `image_tag` should match what you just
   built. If they don't, the container hasn't rolled yet, or the image name is
   wrong.

## Rolling back

Point at the previous tag and restart. Nothing is persisted, so there is no
migration to undo — with one exception: if `LOSEIT_URL_SECRET` changed, every
issued credential URL is already invalid and rolling back will not restore
them.
