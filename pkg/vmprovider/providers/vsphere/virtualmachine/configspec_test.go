// Copyright (c) 2022 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package virtualmachine_test

import (
	goctx "context"
	"encoding/base64"
	"reflect"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"github.com/go-logr/logr"
	vmopv1 "github.com/vmware-tanzu/vm-operator-api/api/v1alpha1"
	vimtypes "github.com/vmware/govmomi/vim25/types"
	"github.com/vmware/govmomi/vim25/xml"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/vmware-tanzu/vm-operator/pkg/context"
	"github.com/vmware-tanzu/vm-operator/pkg/lib"
	"github.com/vmware-tanzu/vm-operator/pkg/vmprovider/providers/vsphere/virtualmachine"
	"github.com/vmware-tanzu/vm-operator/test/builder"
)

var _ = Describe("CreateConfigSpec", func() {
	const vmName = "dummy-vm"

	var (
		vmClassSpec *vmopv1.VirtualMachineClassSpec
		minCPUFreq  uint64
		configSpec  *vimtypes.VirtualMachineConfigSpec
	)

	BeforeEach(func() {
		vmClass := builder.DummyVirtualMachineClass()
		vmClassSpec = &vmClass.Spec
		minCPUFreq = 2500
	})

	JustBeforeEach(func() {
		configSpec = virtualmachine.CreateConfigSpec(
			vmName,
			vmClassSpec,
			minCPUFreq)
		Expect(configSpec).ToNot(BeNil())
	})

	It("Basic ConfigSpec assertions", func() {
		Expect(configSpec.Name).To(Equal(vmName))
		Expect(configSpec.Annotation).ToNot(BeEmpty())
		Expect(configSpec.NumCPUs).To(BeEquivalentTo(vmClassSpec.Hardware.Cpus))
		Expect(configSpec.MemoryMB).To(BeEquivalentTo(4 * 1024))
		Expect(configSpec.CpuAllocation).ToNot(BeNil())
		Expect(configSpec.MemoryAllocation).ToNot(BeNil())
	})
})

var _ = Describe("CreateConfigSpecForPlacement", func() {

	var (
		vmCtx               context.VirtualMachineContext
		vmClassSpec         *vmopv1.VirtualMachineClassSpec
		minCPUFreq          uint64
		storageClassesToIDs map[string]string
		configSpec          *vimtypes.VirtualMachineConfigSpec
	)

	BeforeEach(func() {
		vmClass := builder.DummyVirtualMachineClass()
		vmClassSpec = &vmClass.Spec
		minCPUFreq = 2500
		storageClassesToIDs = map[string]string{}

		vm := builder.DummyVirtualMachine()
		vmCtx = context.VirtualMachineContext{
			Context: goctx.Background(),
			Logger:  logr.New(logf.NullLogSink{}),
			VM:      vm,
		}
	})

	JustBeforeEach(func() {
		configSpec = virtualmachine.CreateConfigSpecForPlacement(
			vmCtx,
			vmClassSpec,
			minCPUFreq,
			storageClassesToIDs)
		Expect(configSpec).ToNot(BeNil())
	})

	Context("When InstanceStorage is configured", func() {
		const storagePolicyID = "storage-id-42"
		var oldIsInstanceStorageFSSEnabled func() bool

		BeforeEach(func() {
			oldIsInstanceStorageFSSEnabled = lib.IsInstanceStorageFSSEnabled
			lib.IsInstanceStorageFSSEnabled = func() bool { return true }

			builder.AddDummyInstanceStorageVolume(vmCtx.VM)
			storageClassesToIDs[builder.DummyStorageClassName] = storagePolicyID
		})

		AfterEach(func() {
			lib.IsInstanceStorageFSSEnabled = oldIsInstanceStorageFSSEnabled
		})

		It("ConfigSpec contains expected InstanceStorage devices", func() {
			Expect(configSpec.DeviceChange).To(HaveLen(3))
			assertInstanceStorageDeviceChange(configSpec.DeviceChange[1], 256, storagePolicyID)
			assertInstanceStorageDeviceChange(configSpec.DeviceChange[2], 512, storagePolicyID)
		})
	})
})

var _ = Describe("ConfigSpec Util", func() {
	Context("MarshalConfigSpec", func() {
		It("marshals and unmarshal to the same spec", func() {
			inputSpec := vimtypes.VirtualMachineConfigSpec{Name: "dummy-VM"}
			bytes, err := virtualmachine.MarshalConfigSpec(inputSpec)
			Expect(err).ShouldNot(HaveOccurred())
			var outputSpec vimtypes.VirtualMachineConfigSpec
			err = xml.Unmarshal(bytes, &outputSpec)
			Expect(err).ShouldNot(HaveOccurred())
			Expect(reflect.DeepEqual(inputSpec, outputSpec)).To(Equal(true))
		})

		It("marshals spec correctly to expected base64 encoded XML", func() {
			inputSpec := vimtypes.VirtualMachineConfigSpec{Name: "dummy-VM"}
			bytes, err := virtualmachine.MarshalConfigSpec(inputSpec)
			Expect(err).ShouldNot(HaveOccurred())
			Expect(base64.StdEncoding.EncodeToString(bytes)).To(Equal("PG9iaiB4bWxuczp2aW0yNT0idXJuOnZpbTI1I" +
				"iB4bWxuczp4c2k9Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvWE1MU2NoZW1hLWluc3RhbmNlIiB4c2k6dHlwZT0idmltMjU6Vmlyd" +
				"HVhbE1hY2hpbmVDb25maWdTcGVjIj48bmFtZT5kdW1teS1WTTwvbmFtZT48L29iaj4="))
		})
	})
})

var _ = Describe("DecodeAndUnmarshalConfigSpec", func() {
	var vmCtx context.VirtualMachineContext

	BeforeEach(func() {
		vmCtx = context.VirtualMachineContext{
			Context: goctx.Background(),
			Logger:  logr.New(logf.NullLogSink{}),
		}
	})

	Context("with an invalid base64 encoded string", func() {
		It("returns corrupt input error while decoding", func() {
			fakeEncodedSpec := "fake-incorrect-configspec"

			configSpec, err := virtualmachine.DecodeAndUnmarshalConfigSpec(vmCtx, fakeEncodedSpec)
			Expect(err).To(HaveOccurred())
			_, ok := err.(base64.CorruptInputError)
			Expect(ok).To(BeTrue())
			Expect(configSpec).To(BeNil())
		})

	})

	Context("with a valid, base64 encoded ConfigSpec XML", func() {
		It("successfully unmarshals", func() {
			inputSpec := vimtypes.VirtualMachineConfigSpec{Name: "dummy-VM"}
			bytes, err := virtualmachine.MarshalConfigSpec(inputSpec)
			Expect(err).ShouldNot(HaveOccurred())
			fakeEncodedConfigSpecXML := base64.StdEncoding.EncodeToString(bytes)

			configSpec, err := virtualmachine.DecodeAndUnmarshalConfigSpec(vmCtx, fakeEncodedConfigSpecXML)
			Expect(err).ToNot(HaveOccurred())
			Expect(configSpec).ToNot(BeNil())
		})
	})
})

func assertInstanceStorageDeviceChange(
	deviceChange vimtypes.BaseVirtualDeviceConfigSpec,
	expectedSizeGB int,
	expectedStoragePolicyID string) {

	dc := deviceChange.GetVirtualDeviceConfigSpec()
	Expect(dc.Operation).To(Equal(vimtypes.VirtualDeviceConfigSpecOperationAdd))
	Expect(dc.FileOperation).To(Equal(vimtypes.VirtualDeviceConfigSpecFileOperationCreate))

	dev, ok := dc.Device.(*vimtypes.VirtualDisk)
	Expect(ok).To(BeTrue())
	Expect(dev.CapacityInBytes).To(BeEquivalentTo(expectedSizeGB * 1024 * 1024 * 1024))

	Expect(dc.Profile).To(HaveLen(1))
	profile, ok := dc.Profile[0].(*vimtypes.VirtualMachineDefinedProfileSpec)
	Expect(ok).To(BeTrue())
	Expect(profile.ProfileId).To(Equal(expectedStoragePolicyID))
}