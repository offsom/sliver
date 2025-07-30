package traffic

/*
	Sliver Implant Framework
	Copyright (C) 2021  Bishop Fox

	This program is free software: you can redistribute it and/or modify
	it under the terms of the GNU General Public License as published by
	the Free Software Foundation, either version 3 of the License, or
	(at your option) any later version.

	This program is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.

	You should have received a copy of the GNU General Public License
	along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

import (
	"context"
	"crypto/sha256"
	"fmt"
	"log"
	"sync"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
)

// CalculateWasmEncoderID - Calculate a unique ID for the wasm encoder
func CalculateWasmEncoderID(wasmEncoderData []byte) uint64 {
	hash := sha256.Sum256(wasmEncoderData)
	return uint64(hash[0]) | uint64(hash[1])<<8 | uint64(hash[2])<<16 | uint64(hash[3])<<24 |
		uint64(hash[4])<<32 | uint64(hash[5])<<40 | uint64(hash[6])<<48 | uint64(hash[7])<<56
}

type TrafficEncoder struct {
	ctx     context.Context
	runtime wazero.Runtime
	mod     api.Module
	lock    sync.Mutex

	// WASM functions
	encoder api.Function
	decoder api.Function
	malloc  api.Function
	free    api.Function
}

// Encode - Encode data using the wasm backend
func (t *TrafficEncoder) Encode(data []byte) ([]byte, error) {
	t.lock.Lock()
	defer t.lock.Unlock()

	// Allocate a buffer in the wasm runtime for the input data
	size := uint64(len(data))
	buf, err := t.malloc.Call(t.ctx, size)
	if err != nil {
		return nil, fmt.Errorf("failed to allocate memory: %w", err)
	}
	bufPtr := buf[0]

	// Ensure memory is freed even if an error occurs
	defer func() {
		if _, freeErr := t.free.Call(t.ctx, bufPtr); freeErr != nil {
			// {{if .Config.Debug}}
			log.Printf("Failed to free memory: %v", freeErr)
			// {{end}}
		}
	}()

	// Copy input data into wasm memory
	if !t.mod.Memory().Write(uint32(bufPtr), data) {
		return nil, fmt.Errorf("Memory.Write(%d, %d) out of range of memory size %d",
			bufPtr, size, t.mod.Memory().Size())
	}

	// Call the encoder function
	ptrSize, err := t.encoder.Call(t.ctx, bufPtr, size)
	if err != nil {
		return nil, fmt.Errorf("encoder function failed: %w", err)
	}

	// Read the output buffer from wasm memory
	encodeResultPtr := uint32(ptrSize[0] >> 32)
	encodeResultSize := uint32(ptrSize[0])

	// Validate memory bounds
	if encodeResultPtr+encodeResultSize > t.mod.Memory().Size() {
		return nil, fmt.Errorf("encoder result out of memory bounds")
	}

	var encodeResult []byte
	var ok bool
	if encodeResult, ok = t.mod.Memory().Read(encodeResultPtr, encodeResultSize); !ok {
		return nil, fmt.Errorf("Memory.Read(%d, %d) out of range of memory size %d",
			encodeResultPtr, encodeResultSize, t.mod.Memory().Size())
	}

	// Make a copy of the result to avoid memory issues
	resultCopy := make([]byte, len(encodeResult))
	copy(resultCopy, encodeResult)

	return resultCopy, nil
}

// Decode - Decode bytes using the wasm backend
func (t *TrafficEncoder) Decode(data []byte) ([]byte, error) {
	t.lock.Lock()
	defer t.lock.Unlock()

	size := uint64(len(data))
	buf, err := t.malloc.Call(t.ctx, size)
	if err != nil {
		return nil, fmt.Errorf("failed to allocate memory: %w", err)
	}
	bufPtr := buf[0]

	// Ensure memory is freed even if an error occurs
	defer func() {
		if _, freeErr := t.free.Call(t.ctx, bufPtr); freeErr != nil {
			// {{if .Config.Debug}}
			log.Printf("Failed to free memory: %v", freeErr)
			// {{end}}
		}
	}()

	if !t.mod.Memory().Write(uint32(bufPtr), data) {
		return nil, fmt.Errorf("Memory.Write(%d, %d) out of range of memory size %d",
			bufPtr, size, t.mod.Memory().Size())
	}

	// Call the decoder function
	ptrSize, err := t.decoder.Call(t.ctx, bufPtr, size)
	if err != nil {
		return nil, fmt.Errorf("decoder function failed: %w", err)
	}

	decodeResultPtr := uint32(ptrSize[0] >> 32)
	decodeResultSize := uint32(ptrSize[0])

	// Validate memory bounds
	if decodeResultPtr+decodeResultSize > t.mod.Memory().Size() {
		return nil, fmt.Errorf("decoder result out of memory bounds")
	}

	var decodeResult []byte
	var ok bool
	if decodeResult, ok = t.mod.Memory().Read(decodeResultPtr, decodeResultSize); !ok {
		return nil, fmt.Errorf("Memory.Read(%d, %d) out of range of memory size %d",
			decodeResultPtr, decodeResultSize, t.mod.Memory().Size())
	}

	// Make a copy of the result to avoid memory issues
	resultCopy := make([]byte, len(decodeResult))
	copy(resultCopy, decodeResult)

	return resultCopy, nil
}

func (t *TrafficEncoder) Close() error {
	return t.runtime.Close(t.ctx)
}

// TrafficEncoderLogCallback - Callback function exposed to the wasm runtime to log messages
type TrafficEncoderLogCallback func(string)
