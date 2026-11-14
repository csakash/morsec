#!/bin/sh
# Charges a test card. The key comes from the environment (.env holds an ms:// reference).
curl -s https://api.stripe.com/v1/charges -u "$STRIPE_SECRET_KEY:" -d amount=100 -d currency=usd -d source=tok_visa
