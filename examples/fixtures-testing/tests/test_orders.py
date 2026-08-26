"""
Offline tests for ShopClient order operations using stubsmith.replay().

Routes covered:
  POST /api/orders             - static, creates an order
  GET  /api/orders/{id}        - dynamic, fetches one order by id
  GET  /api/orders?status=...  - static query-string path, list with filter
  PUT  /api/orders/{id}        - dynamic, updates order status

Order IDs are bare integers (5234, 6102, ...) so the SDK templates
/api/orders/5234 → /api/orders/{id} (entirely numeric segment → {id}).
Dynamic routes (GET and PUT /api/orders/{id}) have path_template "/api/orders/{id}"
in the bundle.  replay() applies the same templating to incoming test requests,
so a call to /api/orders/5234 matches the stub for /api/orders/{id}.

The list_orders fingerprint (15d2fd0d27a9595f) was computed from the query
parameter names [limit, status] - not their values.  Any request with those
two query parameters matches the same stub, regardless of the filter value
passed.

"""
import stubsmith
from shopclient import ShopClient

BASE_URL = "http://localhost:8081"


# ---------------------------------------------------------------------------
# POST /api/orders - 201
# ---------------------------------------------------------------------------


def test_create_order_returns_recorded_shape():
    """Client parses the create-order response including the nested items array."""
    with stubsmith.replay():
        order = ShopClient(BASE_URL, "test-key").create_order(
            "widget-pro", 3, "4242424242424242", "leave at door"
        )

    assert "order_id" in order
    assert order["status"] == "confirmed"
    assert "total_cents" in order
    # customer_email is masked by the regex backstop (email-shaped string).
    assert "customer_email" in order
    assert order["customer_email"] == "<masked>"
    assert "created_at" in order
    # items is a nested array - check structure, not values.
    assert isinstance(order.get("items"), list)
    assert len(order["items"]) > 0
    item = order["items"][0]
    assert "sku" in item
    assert "qty" in item
    assert "price_cents" in item


# ---------------------------------------------------------------------------
# GET /api/orders/{id} - 200 (dynamic route)
# ---------------------------------------------------------------------------


def test_get_order_returns_recorded_shape():
    """replay() templates /api/orders/5234 to /api/orders/{id} for lookup.

    The concrete id is irrelevant to the stub match - any integer id produces
    the same response from the bundle.
    """
    with stubsmith.replay():
        order = ShopClient(BASE_URL, "test-key").get_order(5234)

    assert "order_id" in order
    assert order["status"] == "shipped"
    assert isinstance(order["items"], list)
    assert len(order["items"]) > 0
    assert "sku" in order["items"][0]
    assert "qty" in order["items"][0]
    assert "price_cents" in order["items"][0]
    assert "total_cents" in order
    assert "customer_email" in order


def test_get_order_dynamic_match_any_id():
    """The same stub is served regardless of which integer order id is passed.

    This is the payoff of dynamic path templating: one bundle stub covers all
    id variants in the test suite.  Both calls hit /api/orders/{id}.
    """
    with stubsmith.replay():
        client = ShopClient(BASE_URL, "test-key")
        # Both integer ids template to /api/orders/{id} and hit the same stub.
        order_a = client.get_order(5234)
        order_b = client.get_order(6102)

    # Both return the same recorded shape because both requests matched the
    # same /api/orders/{id} stub - one captured body, served twice.  The
    # equality check is intentionally on order_id: if the templating ever
    # stops firing (e.g. the segment is no longer numeric), the two calls
    # would hit different stubs (or one would StubNotFound), which is the
    # regression this test is designed to catch.
    assert order_a["order_id"] == order_b["order_id"]
    assert "status" in order_a
    assert "status" in order_b


# ---------------------------------------------------------------------------
# GET /api/orders?status=shipped&limit=20 - 200 (query-string fingerprint)
# ---------------------------------------------------------------------------


def test_list_orders_returns_recorded_shape():
    """The query parameter names [limit, status] form the fingerprint (15d2fd0d27a9595f).

    replay() sees the full URL including the query string, extracts the
    parameter names (not values) for fingerprinting, and matches the stub.
    The filter value "shipped" appears in the response because the operator
    added a keep rule for query.status in the example project.
    """
    with stubsmith.replay():
        result = ShopClient(BASE_URL, "test-key").list_orders(
            status="shipped", limit=20
        )

    assert isinstance(result["orders"], list)
    assert result["total"] == len(result["orders"])
    for order in result["orders"]:
        assert "order_id" in order
        assert "status" in order


# ---------------------------------------------------------------------------
# PUT /api/orders/{id} - 200 (dynamic route)
# ---------------------------------------------------------------------------


def test_update_order_returns_recorded_shape():
    """Client parses the update-order response correctly.

    PUT /api/orders/{id} is dynamic; replay() templates 5234 → {id}.
    """
    with stubsmith.replay():
        result = ShopClient(BASE_URL, "test-key").update_order(5234, "cancelled")

    assert "order_id" in result
    assert result["status"] == "cancelled"
