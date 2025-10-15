.PHONY: help init build start stop clean logs shell-ap shell-sta shell-capture analyze status

help:
	@echo "=== Testbed Management Commands ==="
	@echo "  make init      - Initialize mac80211_hwsim module"
	@echo "  make build     - Build Docker images from source"
	@echo "  make start     - Start all containers and assign interfaces"
	@echo "  make stop      - Stop all containers and cleanup"
	@echo "  make clean     - Complete cleanup (containers, images, volumes)"
	@echo "  make logs      - Show all container logs"
	@echo "  make status    - Show system status"
	@echo ""
	@echo "=== Container Access ==="
	@echo "  make shell-sta     - Open shell in STA container"
	@echo "  make shell-ap      - Open shell in AP container"
	@echo "  make shell-capture - Open shell in capture container"
	@echo ""
	@echo "=== Analysis ==="
	@echo "  make analyze   - Open Wireshark with captured packets"
	@echo "  make capture-status - Show capture file status"

init:
	@echo "Initializing mac80211_hwsim..."
	./init-hwsim.sh

build:
	@echo "Building Docker images from hostap source..."
	docker compose build

start: init build
	@echo "Starting containers..."
	docker compose up -d
	@echo "Waiting for containers to initialize..."
	sleep 8
	@echo "Assigning hwsim interfaces to containers..."
	./assign-interfaces.sh
	@echo ""
	@echo "=== Testbed is ready! ==="
	@echo "Monitor the connection with: make logs"
	@echo "Check status with: make status"

stop:
	@echo "Stopping containers..."
	docker compose down
	@echo "Removing mac80211_hwsim module..."
	sudo modprobe -r mac80211_hwsim 2>/dev/null || true

clean: stop
	@echo "Cleaning up Docker resources..."
	docker compose down -v
	@echo "Cleanup complete"

restart: stop start

logs:
	docker compose logs -f

logs-sta:
	docker compose logs -f testbed_sta

logs-ap:
	docker compose logs -f testbed_ap

logs-capture:
	docker compose logs -f testbed_capture

shell-sta:
	docker exec -it testbed_sta /bin/bash

shell-ap:
	docker exec -it testbed_ap /bin/bash

shell-capture:
	docker exec -it testbed_capture /bin/bash

analyze:
	@echo "Opening Wireshark with captured packets..."
	wireshark captures/*.pcap 2>/dev/null &

status:
	@echo "=== Container Status ==="
	docker compose ps
	@echo ""
	@echo "=== STA Interface Status ==="
	docker exec testbed_sta iw dev 2>/dev/null || echo "STA not running or interface not assigned"
	@echo ""
	@echo "=== AP Interface Status ==="
	docker exec testbed_ap iw dev 2>/dev/null || echo "AP not running or interface not assigned"
	@echo ""
	@echo "=== Capture Interface Status ==="
	docker exec testbed_capture iw dev 2>/dev/null || echo "Capture not running or interface not assigned"
	@echo ""
	@echo "=== Connection Status ==="
	docker exec testbed_sta iw wlan0 link 2>/dev/null || echo "STA not connected"

capture-status:
	@echo "=== Capture Files ==="
	@ls -lh captures/*.pcap 2>/dev/null || echo "No captures yet"
	@echo ""
	@echo "=== Packet Counts ==="
	@for f in captures/*.pcap; do \
		if [ -f "$$f" ]; then \
			echo "$$f: $$(tcpdump -r $$f 2>/dev/null | wc -l) packets"; \
		fi \
	done

test-connection:
	@echo "Testing STA to AP connectivity..."
	docker exec testbed_sta ping -c 4 -W 2 192.168.100.1

test:
	./test-connection.sh

trigger-handshake:
	./trigger-handshake.sh