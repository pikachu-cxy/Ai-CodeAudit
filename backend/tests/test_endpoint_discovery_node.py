"""Unit tests for Node.js (Express / NestJS / Koa) endpoint discovery."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from app.services.endpoint_discovery_service import (
    _CONTROLLER_CACHE,
    _EXPRESS_MOUNT_CACHE,
    discover_controller_units,
)


class NodeEndpointDiscoveryTests(unittest.TestCase):
    def setUp(self) -> None:
        _CONTROLLER_CACHE.clear()
        _EXPRESS_MOUNT_CACHE.clear()
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)

    def tearDown(self) -> None:
        self.tmp.cleanup()
        _CONTROLLER_CACHE.clear()
        _EXPRESS_MOUNT_CACHE.clear()

    def _write(self, rel: str, content: str) -> Path:
        path = self.root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        return path

    def test_express_single_file_routes(self) -> None:
        self._write(
            "routes/users.js",
            """
const express = require('express');
const router = express.Router();
const userController = require('../controllers/user');

router.get('/list', userController.list);
router.post('/login', async (req, res) => res.json({ ok: true }));
app.get('/health', (req, res) => res.send('ok'));

module.exports = router;
""",
        )
        units = discover_controller_units(self.root)
        self.assertEqual(len(units), 1)
        paths = {ep.path for ep in units[0].endpoints}
        methods = {ep.http_method for ep in units[0].endpoints}
        self.assertIn("/list", paths)
        self.assertIn("/login", paths)
        self.assertIn("/health", paths)
        self.assertIn("GET", methods)
        self.assertIn("POST", methods)

    def test_express_app_use_mount_prefix(self) -> None:
        self._write(
            "app.js",
            """
const express = require('express');
const app = express();
app.use('/api/users', require('./routes/users'));
module.exports = app;
""",
        )
        self._write(
            "routes/users.js",
            """
const express = require('express');
const router = express.Router();
router.get('/list', (req, res) => res.json([]));
module.exports = router;
""",
        )
        units = discover_controller_units(self.root)
        self.assertEqual(len(units), 1)
        self.assertEqual(units[0].endpoints[0].path, "/api/users/list")

    def test_nestjs_controller_decorators(self) -> None:
        self._write(
            "src/users/users.controller.ts",
            """
import { Controller, Get, Post, Param } from '@nestjs/common';

@Controller('users')
export class UsersController {
  @Get()
  findAll() {
    return [];
  }

  @Get(':id')
  findOne(@Param('id') id: string) {
    return { id };
  }

  @Post('create')
  create() {
    return {};
  }
}
""",
        )
        units = discover_controller_units(self.root)
        self.assertEqual(len(units), 1)
        self.assertEqual(units[0].class_name, "UsersController")
        paths = {ep.path for ep in units[0].endpoints}
        self.assertIn("/users", paths)
        self.assertIn("/users/:id", paths)
        self.assertIn("/users/create", paths)

    def test_koa_router_routes(self) -> None:
        self._write(
            "routes/koa.js",
            """
const Router = require('@koa/router');
const router = new Router();

router.get('/items', async (ctx) => { ctx.body = []; });
router.post('/items', async (ctx) => { ctx.body = {}; });

module.exports = router;
""",
        )
        units = discover_controller_units(self.root)
        self.assertEqual(len(units), 1)
        paths = {ep.path for ep in units[0].endpoints}
        self.assertIn("/items", paths)
        self.assertEqual(len(units[0].endpoints), 2)

    def test_mixed_java_and_express(self) -> None:
        self._write(
            "src/main/java/com/example/UserController.java",
            """
@RestController
public class UserController {
    @GetMapping("/java/users/list")
    public List<User> list() { return null; }
}
""",
        )
        self._write(
            "routes/api.js",
            """
const express = require('express');
const app = express();
app.get('/node/ping', (req, res) => res.send('pong'));
""",
        )
        units = discover_controller_units(self.root)
        self.assertEqual(len(units), 2)
        all_paths = {ep.path for u in units for ep in u.endpoints}
        self.assertIn("/java/users/list", all_paths)
        self.assertIn("/node/ping", all_paths)

    def test_express_route_chain(self) -> None:
        self._write(
            "routes/chain.js",
            """
const express = require('express');
const router = express.Router();
router.route('/users').get((req, res) => res.json([])).post((req, res) => res.json({}));
module.exports = router;
""",
        )
        units = discover_controller_units(self.root)
        self.assertEqual(len(units), 1)
        get_eps = [ep for ep in units[0].endpoints if ep.http_method == "GET"]
        self.assertTrue(any(ep.path == "/users" for ep in get_eps))


if __name__ == "__main__":
    unittest.main()
