// Copyright (c) 2022 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package vsphere_test

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/rand"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	. "github.com/onsi/gomega/gstruct"

	vmopv1alpha1 "github.com/vmware-tanzu/vm-operator-api/api/v1alpha1"
	"github.com/vmware/govmomi/object"
	"github.com/vmware/govmomi/vapi/cluster"
	"github.com/vmware/govmomi/vim25/mo"
	"github.com/vmware/govmomi/vim25/types"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/pointer"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/vmware-tanzu/vm-operator/pkg/topology"
	"github.com/vmware-tanzu/vm-operator/pkg/vmprovider"
	"github.com/vmware-tanzu/vm-operator/pkg/vmprovider/providers/vsphere"
	"github.com/vmware-tanzu/vm-operator/pkg/vmprovider/providers/vsphere/constants"
	"github.com/vmware-tanzu/vm-operator/pkg/vmprovider/providers/vsphere/instancestorage"
	"github.com/vmware-tanzu/vm-operator/pkg/vmprovider/providers/vsphere/virtualmachine"
	"github.com/vmware-tanzu/vm-operator/test/builder"
)

func vmTests() {

	const (
		dvpgName = "DC0_DVPG0"
	)

	var (
		initObjects []client.Object
		testConfig  builder.VCSimTestConfig
		ctx         *builder.TestContextForVCSim
		vmProvider  vmprovider.VirtualMachineProviderInterface
		nsInfo      builder.WorkloadNamespaceInfo
	)

	BeforeEach(func() {
		testConfig = builder.VCSimTestConfig{}
	})

	JustBeforeEach(func() {
		ctx = suite.NewTestContextForVCSim(testConfig, initObjects...)
		vmProvider = vsphere.NewVSphereVMProviderFromClient(ctx.Client, ctx.Recorder)
		nsInfo = ctx.CreateWorkloadNamespace()
	})

	AfterEach(func() {
		ctx.AfterEach()
		ctx = nil
		initObjects = nil
		vmProvider = nil
		nsInfo = builder.WorkloadNamespaceInfo{}
	})

	Context("Create/Update/Delete VirtualMachine", func() {
		var (
			vm *vmopv1alpha1.VirtualMachine
		)

		BeforeEach(func() {
			testConfig.WithContentLibrary = true
			vm = builder.DummyBasicVirtualMachine("test-vm", "")
		})

		AfterEach(func() {
			vm = nil
		})

		JustBeforeEach(func() {
			vmClass := builder.DummyVirtualMachineClass()
			Expect(ctx.Client.Create(ctx, vmClass)).To(Succeed())

			vmClassBinding := builder.DummyVirtualMachineClassBinding(vmClass.Name, nsInfo.Namespace)
			Expect(ctx.Client.Create(ctx, vmClassBinding)).To(Succeed())

			vmImage := &vmopv1alpha1.VirtualMachineImage{}
			if testConfig.WithContentLibrary {
				Expect(ctx.Client.Get(ctx, client.ObjectKey{Name: ctx.ContentLibraryImageName}, vmImage)).To(Succeed())
			} else {
				// BMV: Without a CL is broken - and has been for a long while - since we assume the
				// VM Image will always have a ContentLibraryProvider owner. Hack around that here so
				// we can continue to test the VM clone path.
				vsphere.SkipVMImageCLProviderCheck = true

				// Use the default VM by vcsim as the source.
				vmImage = builder.DummyVirtualMachineImage("DC0_C0_RP0_VM0")
				Expect(ctx.Client.Create(ctx, vmImage)).To(Succeed())
			}

			vm.Namespace = nsInfo.Namespace
			vm.Spec.ClassName = vmClass.Name
			vm.Spec.ImageName = vmImage.Name
			vm.Spec.StorageClass = ctx.StorageClassName
		})

		AfterEach(func() {
			vsphere.SkipVMImageCLProviderCheck = false
		})

		createOrUpdateAndGetVcVM := func(
			ctx *builder.TestContextForVCSim,
			vm *vmopv1alpha1.VirtualMachine) (*object.VirtualMachine, error) {

			err := vmProvider.CreateOrUpdateVirtualMachine(ctx, vm)
			if err != nil {
				return nil, err
			}

			ExpectWithOffset(1, vm.Status.UniqueID).ToNot(BeEmpty())
			vcVM := ctx.GetVMFromMoID(vm.Status.UniqueID)
			ExpectWithOffset(1, vcVM).ToNot(BeNil())
			return vcVM, nil
		}

		Context("VMClassAsConfig FSS is enabled", func() {

			var (
				vcVM       *object.VirtualMachine
				configSpec *types.VirtualMachineConfigSpec
			)

			BeforeEach(func() {
				testConfig.WithVMClassAsConfig = true
			})

			JustBeforeEach(func() {
				if configSpec != nil {
					bytes, err := virtualmachine.MarshalConfigSpec(*configSpec)
					Expect(err).ToNot(HaveOccurred())

					// Update the VM Class with the XML.
					vmClass := &vmopv1alpha1.VirtualMachineClass{}
					Expect(ctx.Client.Get(ctx, client.ObjectKey{Name: vm.Spec.ClassName}, vmClass)).To(Succeed())
					vmClass.Spec.ConfigSpec = &vmopv1alpha1.VirtualMachineConfigSpec{
						XML: base64.StdEncoding.EncodeToString(bytes),
					}
					Expect(ctx.Client.Update(ctx, vmClass)).To(Succeed())
				}

				vm.Spec.NetworkInterfaces = []vmopv1alpha1.VirtualMachineNetworkInterface{
					{
						// Use the DVPG network so the updateEthCardDeviceChanges detects a device change.
						// If we use the "VM Network", then it won't detect any device changes since we
						// only compare the device name and not the type of the ethernet card.
						NetworkName: dvpgName,
					},
				}

				var err error
				vcVM, err = createOrUpdateAndGetVcVM(ctx, vm)
				Expect(err).ToNot(HaveOccurred())
			})

			AfterEach(func() {
				vcVM = nil
				configSpec = nil
			})

			Context("VM Class has no ConfigSpec", func() {
				BeforeEach(func() {
					configSpec = nil
				})

				It("still creates VM", func() {
					Expect(vm.Status.Phase).To(Equal(vmopv1alpha1.Created))

					vmClass := &vmopv1alpha1.VirtualMachineClass{}
					Expect(ctx.Client.Get(ctx, client.ObjectKey{Name: vm.Spec.ClassName}, vmClass)).To(Succeed())

					var o mo.VirtualMachine
					Expect(vcVM.Properties(ctx, vcVM.Reference(), nil, &o)).To(Succeed())
					Expect(o.Summary.Config.NumCpu).To(BeEquivalentTo(vmClass.Spec.Hardware.Cpus))
					Expect(o.Summary.Config.MemorySizeMB).To(BeEquivalentTo(vmClass.Spec.Hardware.Memory.Value() / 1024 / 1024))
				})
			})

			Context("VM Class ConfigSpec specifies a network interface", func() {
				var ethCard types.VirtualEthernetCard

				BeforeEach(func() {
					ethCard = types.VirtualEthernetCard{
						VirtualDevice: types.VirtualDevice{
							Key: 4000,
							DeviceInfo: &types.Description{
								Label:   "test-configspec-nic-label",
								Summary: "VM Network",
							},
							SlotInfo: &types.VirtualDevicePciBusSlotInfo{
								VirtualDeviceBusSlotInfo: types.VirtualDeviceBusSlotInfo{},
								PciSlotNumber:            32,
							},
							ControllerKey: 100,
						},
						AddressType: string(types.VirtualEthernetCardMacTypeGenerated),
						MacAddress:  "00:0c:29:93:d7:27",
					}

					// Create the ConfigSpec with an ethernet card.
					configSpec = &types.VirtualMachineConfigSpec{
						Name: "dummy-VM",
						DeviceChange: []types.BaseVirtualDeviceConfigSpec{
							&types.VirtualDeviceConfigSpec{
								Operation: types.VirtualDeviceConfigSpecOperationAdd,
								Device: &types.VirtualE1000{
									VirtualEthernetCard: ethCard,
								},
							},
						},
					}
				})

				It("Reconfigures the VM with the NIC specified in ConfigSpec", func() {
					var o mo.VirtualMachine
					Expect(vcVM.Properties(ctx, vcVM.Reference(), nil, &o)).To(Succeed())

					devList := object.VirtualDeviceList(o.Config.Hardware.Device)
					l := devList.SelectByType(&types.VirtualEthernetCard{})
					Expect(l).To(HaveLen(1))

					dev := l[0].GetVirtualDevice()
					backing, ok := dev.Backing.(*types.VirtualEthernetCardDistributedVirtualPortBackingInfo)
					Expect(ok).Should(BeTrue())
					_, dvpg := getDVPG(ctx, dvpgName)
					Expect(backing.Port.PortgroupKey).To(Equal(dvpg.Reference().Value))

					Expect(l[0].(*types.VirtualE1000).AddressType).To(Equal(ethCard.AddressType))
					Expect(dev.DeviceInfo).To(Equal(ethCard.VirtualDevice.DeviceInfo))
					Expect(dev.DeviceGroupInfo).To(Equal(ethCard.VirtualDevice.DeviceGroupInfo))
					Expect(dev.SlotInfo).To(Equal(ethCard.VirtualDevice.SlotInfo))
					Expect(dev.ControllerKey).To(Equal(ethCard.VirtualDevice.ControllerKey))

					ethDevice, ok := l[0].(*types.VirtualE1000)
					Expect(ok).To(BeTrue())

					// Mac Address should not match with the class from ConfigSpec. It will be updated
					// from the backing generated by the network provider.
					Expect(ethDevice.MacAddress).NotTo(Equal(ethCard.MacAddress))
				})
			})

			Context("ConfigSpec does not specify any network interfaces", func() {

				BeforeEach(func() {
					configSpec = &types.VirtualMachineConfigSpec{
						Name: "dummy-VM",
					}
				})

				It("Reconfigures the VM with the default NIC settings from provider", func() {
					var o mo.VirtualMachine
					Expect(vcVM.Properties(ctx, vcVM.Reference(), nil, &o)).To(Succeed())

					devList := object.VirtualDeviceList(o.Config.Hardware.Device)
					l := devList.SelectByType(&types.VirtualEthernetCard{})
					Expect(l).To(HaveLen(1))

					dev := l[0].GetVirtualDevice()
					backing, ok := dev.Backing.(*types.VirtualEthernetCardDistributedVirtualPortBackingInfo)
					Expect(ok).Should(BeTrue())
					_, dvpg := getDVPG(ctx, dvpgName)
					Expect(backing.Port.PortgroupKey).To(Equal(dvpg.Reference().Value))
				})
			})
		})

		Context("CreateOrUpdate VM", func() {

			It("Basic VM", func() {
				vcVM, err := createOrUpdateAndGetVcVM(ctx, vm)
				Expect(err).ToNot(HaveOccurred())

				var o mo.VirtualMachine
				Expect(vcVM.Properties(ctx, vcVM.Reference(), nil, &o)).To(Succeed())

				By("has expected Status values", func() {
					Expect(vm.Status.Phase).To(Equal(vmopv1alpha1.Created))
					Expect(vm.Status.PowerState).To(Equal(vm.Spec.PowerState))
					Expect(vm.Status.Host).ToNot(BeEmpty())
					Expect(vm.Status.InstanceUUID).To(And(Not(BeEmpty()), Equal(o.Config.InstanceUuid)))
					Expect(vm.Status.BiosUUID).To(And(Not(BeEmpty()), Equal(o.Config.Uuid)))
				})

				By("has expected inventory path", func() {
					Expect(vcVM.InventoryPath).To(HaveSuffix(fmt.Sprintf("/%s/%s", nsInfo.Namespace, vm.Name)))
				})

				By("has expected namespace resource pool", func() {
					rp, err := vcVM.ResourcePool(ctx)
					Expect(err).ToNot(HaveOccurred())
					nsRP := ctx.GetResourcePoolForNamespace(nsInfo.Namespace, "")
					Expect(nsRP).ToNot(BeNil())
					Expect(rp.Reference().Value).To(Equal(nsRP.Reference().Value))
				})

				By("has expected power state", func() {
					Expect(o.Summary.Runtime.PowerState).To(Equal(types.VirtualMachinePowerStatePoweredOn))
				})

				By("has expected hardware config", func() {
					vmClass := &vmopv1alpha1.VirtualMachineClass{}
					Expect(ctx.Client.Get(ctx, client.ObjectKey{Name: vm.Spec.ClassName}, vmClass)).To(Succeed())
					Expect(o.Summary.Config.NumCpu).To(BeEquivalentTo(vmClass.Spec.Hardware.Cpus))
					Expect(o.Summary.Config.MemorySizeMB).To(BeEquivalentTo(vmClass.Spec.Hardware.Memory.Value() / 1024 / 1024))
				})

				// TODO: More assertions!
			})

			Context("Without Content Library", func() {
				BeforeEach(func() {
					testConfig.WithContentLibrary = false
				})

				// TODO: Dedupe this with "Basic VM" above
				It("Clones VM", func() {
					vcVM, err := createOrUpdateAndGetVcVM(ctx, vm)
					Expect(err).ToNot(HaveOccurred())

					var o mo.VirtualMachine
					Expect(vcVM.Properties(ctx, vcVM.Reference(), nil, &o)).To(Succeed())

					By("has expected Status values", func() {
						Expect(vm.Status.Phase).To(Equal(vmopv1alpha1.Created))
						Expect(vm.Status.PowerState).To(Equal(vm.Spec.PowerState))
						Expect(vm.Status.Host).ToNot(BeEmpty())
						Expect(vm.Status.InstanceUUID).To(And(Not(BeEmpty()), Equal(o.Config.InstanceUuid)))
						Expect(vm.Status.BiosUUID).To(And(Not(BeEmpty()), Equal(o.Config.Uuid)))
					})

					By("has expected inventory path", func() {
						Expect(vcVM.InventoryPath).To(HaveSuffix(fmt.Sprintf("/%s/%s", nsInfo.Namespace, vm.Name)))
					})

					By("has expected namespace resource pool", func() {
						rp, err := vcVM.ResourcePool(ctx)
						Expect(err).ToNot(HaveOccurred())
						nsRP := ctx.GetResourcePoolForNamespace(nsInfo.Namespace, "")
						Expect(nsRP).ToNot(BeNil())
						Expect(rp.Reference().Value).To(Equal(nsRP.Reference().Value))
					})

					By("has expected power state", func() {
						Expect(o.Summary.Runtime.PowerState).To(Equal(types.VirtualMachinePowerStatePoweredOn))
					})

					By("has expected hardware config", func() {
						vmClass := &vmopv1alpha1.VirtualMachineClass{}
						Expect(ctx.Client.Get(ctx, client.ObjectKey{Name: vm.Spec.ClassName}, vmClass)).To(Succeed())
						Expect(o.Summary.Config.NumCpu).To(BeEquivalentTo(vmClass.Spec.Hardware.Cpus))
						Expect(o.Summary.Config.MemorySizeMB).To(BeEquivalentTo(vmClass.Spec.Hardware.Memory.Value() / 1024 / 1024))
					})

					// TODO: More assertions!
				})
			})

			It("Create VM from VMTX in ContentLibrary", func() {
				imageName := "test-vm-vmtx"

				ctx.ContentLibraryItemTemplate("DC0_C0_RP0_VM0", imageName)
				vm.Spec.ImageName = imageName

				_, err := createOrUpdateAndGetVcVM(ctx, vm)
				Expect(err).ToNot(HaveOccurred())
			})

			Context("When fault domains is enabled", func() {
				BeforeEach(func() {
					testConfig.WithFaultDomains = true
				})

				It("creates VM in placement selected zone", func() {
					Expect(vm.Labels).ToNot(HaveKey(topology.KubernetesTopologyZoneLabelKey))
					vcVM, err := createOrUpdateAndGetVcVM(ctx, vm)
					Expect(err).ToNot(HaveOccurred())

					azName, ok := vm.Labels[topology.KubernetesTopologyZoneLabelKey]
					Expect(ok).To(BeTrue())
					Expect(azName).To(BeElementOf(ctx.ZoneNames))

					By("VM is created in the zone's ResourcePool", func() {
						rp, err := vcVM.ResourcePool(ctx)
						Expect(err).ToNot(HaveOccurred())
						nsRP := ctx.GetResourcePoolForNamespace(nsInfo.Namespace, azName)
						Expect(nsRP).ToNot(BeNil())
						Expect(rp.Reference().Value).To(Equal(nsRP.Reference().Value))
					})
				})

				It("creates VM in assigned zone", func() {
					azName := ctx.ZoneNames[rand.Intn(len(ctx.ZoneNames))] //nolint:gosec
					vm.Labels[topology.KubernetesTopologyZoneLabelKey] = azName

					vcVM, err := createOrUpdateAndGetVcVM(ctx, vm)
					Expect(err).ToNot(HaveOccurred())

					By("VM is created in the zone's ResourcePool", func() {
						rp, err := vcVM.ResourcePool(ctx)
						Expect(err).ToNot(HaveOccurred())
						nsRP := ctx.GetResourcePoolForNamespace(nsInfo.Namespace, azName)
						Expect(nsRP).ToNot(BeNil())
						Expect(rp.Reference().Value).To(Equal(nsRP.Reference().Value))
					})
				})
			})

			Context("When Instance Storage FSS is enabled", func() {
				BeforeEach(func() {
					testConfig.WithInstanceStorage = true
				})

				expectInstanceStorageVolumes := func(
					vm *vmopv1alpha1.VirtualMachine,
					isStorage vmopv1alpha1.InstanceStorage) {

					ExpectWithOffset(1, isStorage.Volumes).ToNot(BeEmpty())
					isVolumes := instancestorage.FilterVolumes(vm)
					ExpectWithOffset(1, isVolumes).To(HaveLen(len(isStorage.Volumes)))

					for _, isVol := range isStorage.Volumes {
						found := false

						for idx, vol := range isVolumes {
							claim := vol.PersistentVolumeClaim.InstanceVolumeClaim
							if claim.StorageClass == isStorage.StorageClass && claim.Size == isVol.Size {
								isVolumes = append(isVolumes[:idx], isVolumes[idx+1:]...)
								found = true
								break
							}
						}

						ExpectWithOffset(1, found).To(BeTrue(), "failed to find instance storage volume for %v", isVol)
					}
				}

				It("creates VM without instance storage", func() {
					_, err := createOrUpdateAndGetVcVM(ctx, vm)
					Expect(err).ToNot(HaveOccurred())
				})

				It("create VM with instance storage", func() {
					Expect(vm.Spec.Volumes).To(BeEmpty())

					vmClass := &vmopv1alpha1.VirtualMachineClass{}
					Expect(ctx.Client.Get(ctx, client.ObjectKey{Name: vm.Spec.ClassName}, vmClass)).To(Succeed())
					vmClass.Spec.Hardware.InstanceStorage = vmopv1alpha1.InstanceStorage{
						StorageClass: vm.Spec.StorageClass,
						Volumes: []vmopv1alpha1.InstanceStorageVolume{
							{
								Size: resource.MustParse("256Gi"),
							},
							{
								Size: resource.MustParse("512Gi"),
							},
						},
					}
					Expect(ctx.Client.Update(ctx, vmClass)).To(Succeed())

					err := vmProvider.CreateOrUpdateVirtualMachine(ctx, vm)
					Expect(err).To(MatchError("instance storage PVCs are not bound yet"))

					By("Instance storage volumes should be added to VM", func() {
						Expect(instancestorage.IsConfigured(vm)).To(BeTrue())
						expectInstanceStorageVolumes(vm, vmClass.Spec.Hardware.InstanceStorage)
					})
					isVol0 := vm.Spec.Volumes[0]

					By("Placement should have been done", func() {
						Expect(vm.Annotations).To(HaveKey(constants.InstanceStorageSelectedNodeAnnotationKey))
						Expect(vm.Annotations).To(HaveKey(constants.InstanceStorageSelectedNodeMOIDAnnotationKey))
					})

					By("simulate volume controller workflow", func() {
						// Simulate what would be set by volume controller.
						vm.Annotations[constants.InstanceStoragePVCsBoundAnnotationKey] = ""

						err = vmProvider.CreateOrUpdateVirtualMachine(ctx, vm)
						Expect(err).To(HaveOccurred())
						Expect(err.Error()).To(ContainSubstring(fmt.Sprintf("status update pending for persistent volume: %s on VM", isVol0.Name)))

						// Simulate what would be set by the volume controller.
						for _, vol := range vm.Spec.Volumes {
							vm.Status.Volumes = append(vm.Status.Volumes, vmopv1alpha1.VirtualMachineVolumeStatus{
								Name:     vol.Name,
								Attached: true,
							})
						}
					})

					By("VM is now created", func() {
						_, err = createOrUpdateAndGetVcVM(ctx, vm)
						Expect(err).ToNot(HaveOccurred())
					})
				})
			})

			It("Powers VM off", func() {
				vcVM, err := createOrUpdateAndGetVcVM(ctx, vm)
				Expect(err).ToNot(HaveOccurred())

				Expect(vm.Status.PowerState).To(Equal(vmopv1alpha1.VirtualMachinePoweredOn))
				vm.Spec.PowerState = vmopv1alpha1.VirtualMachinePoweredOff
				Expect(vmProvider.CreateOrUpdateVirtualMachine(ctx, vm)).To(Succeed())

				Expect(vm.Status.PowerState).To(Equal(vmopv1alpha1.VirtualMachinePoweredOff))
				state, err := vcVM.PowerState(ctx)
				Expect(err).ToNot(HaveOccurred())
				Expect(state).To(Equal(types.VirtualMachinePowerStatePoweredOff))
			})

			It("returns error when StorageClass is required but none specified", func() {
				vm.Spec.StorageClass = ""
				err := vmProvider.CreateOrUpdateVirtualMachine(ctx, vm)
				Expect(err).To(MatchError("storage class is required but not specified"))
			})

			It("Can be called multiple times", func() {
				vcVM, err := createOrUpdateAndGetVcVM(ctx, vm)
				Expect(err).ToNot(HaveOccurred())

				var o mo.VirtualMachine
				Expect(vcVM.Properties(ctx, vcVM.Reference(), nil, &o)).To(Succeed())
				modified := o.Config.Modified

				_, err = createOrUpdateAndGetVcVM(ctx, vm)
				Expect(err).ToNot(HaveOccurred())
				Expect(vcVM.Properties(ctx, vcVM.Reference(), nil, &o)).To(Succeed())

				// Try to assert nothing changed.
				Expect(o.Config.Modified).To(Equal(modified))
			})

			Context("VM Metadata", func() {

				Context("ExtraConfig Transport", func() {
					var ec map[string]interface{}

					JustBeforeEach(func() {
						configMap := &corev1.ConfigMap{
							ObjectMeta: metav1.ObjectMeta{
								GenerateName: "md-configmap-",
								Namespace:    vm.Namespace,
							},
							Data: map[string]string{
								"foo.bar":       "should-be-ignored",
								"guestinfo.Foo": "foo",
							},
						}
						Expect(ctx.Client.Create(ctx, configMap)).To(Succeed())

						vm.Spec.VmMetadata = &vmopv1alpha1.VirtualMachineMetadata{
							ConfigMapName: configMap.Name,
							Transport:     vmopv1alpha1.VirtualMachineMetadataExtraConfigTransport,
						}
						vcVM, err := createOrUpdateAndGetVcVM(ctx, vm)
						Expect(err).ToNot(HaveOccurred())

						var o mo.VirtualMachine
						Expect(vcVM.Properties(ctx, vcVM.Reference(), nil, &o)).To(Succeed())

						ec = map[string]interface{}{}
						for _, option := range o.Config.ExtraConfig {
							if val := option.GetOptionValue(); val != nil {
								ec[val.Key] = val.Value.(string)
							}
						}
					})

					AfterEach(func() {
						ec = nil
					})

					It("Metadata data is included in ExtraConfig", func() {
						Expect(ec).ToNot(HaveKey("foo.bar"))
						Expect(ec).To(HaveKeyWithValue("guestinfo.Foo", "foo"))

						By("Should include default keys and values", func() {
							Expect(ec).To(HaveKeyWithValue("disk.enableUUID", "TRUE"))
							Expect(ec).To(HaveKeyWithValue("vmware.tools.gosc.ignoretoolscheck", "TRUE"))
						})
					})

					Context("JSON_EXTRA_CONFIG is specified", func() {
						BeforeEach(func() {
							b, err := json.Marshal(
								struct {
									Foo string
									Bar string
								}{
									Foo: "f00",
									Bar: "42",
								},
							)
							Expect(err).ToNot(HaveOccurred())
							testConfig.WithJSONExtraConfig = string(b)
						})

						It("Global config is included in ExtraConfig", func() {
							Expect(ec).To(HaveKeyWithValue("Foo", "f00"))
							Expect(ec).To(HaveKeyWithValue("Bar", "42"))
						})
					})
				})
			})

			Context("Network", func() {

				It("Should not have a nic", func() {
					vcVM, err := createOrUpdateAndGetVcVM(ctx, vm)
					Expect(err).ToNot(HaveOccurred())

					var o mo.VirtualMachine
					Expect(vcVM.Properties(ctx, vcVM.Reference(), nil, &o)).To(Succeed())

					devList := object.VirtualDeviceList(o.Config.Hardware.Device)
					l := devList.SelectByType(&types.VirtualEthernetCard{})
					Expect(l).To(BeEmpty())
				})

				Context("Multiple NICs are specified", func() {
					BeforeEach(func() {
						vm.Spec.NetworkInterfaces = []vmopv1alpha1.VirtualMachineNetworkInterface{
							{
								NetworkName:      "VM Network",
								EthernetCardType: "e1000",
							},
							{
								NetworkName: dvpgName,
							},
						}
					})

					It("Has expected devices", func() {
						vcVM, err := createOrUpdateAndGetVcVM(ctx, vm)
						Expect(err).ToNot(HaveOccurred())

						var o mo.VirtualMachine
						Expect(vcVM.Properties(ctx, vcVM.Reference(), nil, &o)).To(Succeed())

						devList := object.VirtualDeviceList(o.Config.Hardware.Device)
						l := devList.SelectByType(&types.VirtualEthernetCard{})
						Expect(l).To(HaveLen(2))

						dev1 := l[0].GetVirtualDevice()
						backing1, ok := dev1.Backing.(*types.VirtualEthernetCardNetworkBackingInfo)
						Expect(ok).Should(BeTrue())
						Expect(backing1.DeviceName).To(Equal("VM Network"))

						dev2 := l[1].GetVirtualDevice()
						backing2, ok := dev2.Backing.(*types.VirtualEthernetCardDistributedVirtualPortBackingInfo)
						Expect(ok).Should(BeTrue())
						_, dvpg := getDVPG(ctx, dvpgName)
						Expect(backing2.Port.PortgroupKey).To(Equal(dvpg.Reference().Value))
					})
				})
			})

			Context("Disks", func() {

				Context("VM has thin provisioning", func() {
					BeforeEach(func() {
						vm.Spec.AdvancedOptions = &vmopv1alpha1.VirtualMachineAdvancedOptions{
							DefaultVolumeProvisioningOptions: &vmopv1alpha1.VirtualMachineVolumeProvisioningOptions{
								ThinProvisioned: pointer.Bool(true),
							},
						}
					})

					It("Succeeds", func() {
						vcVM, err := createOrUpdateAndGetVcVM(ctx, vm)
						Expect(err).ToNot(HaveOccurred())

						var o mo.VirtualMachine
						Expect(vcVM.Properties(ctx, vcVM.Reference(), nil, &o)).To(Succeed())

						_, backing := getVMHomeDisk(ctx, vcVM, o)
						Expect(backing.ThinProvisioned).To(PointTo(BeTrue()))
					})
				})

				XContext("VM has thick provisioning", func() {
					BeforeEach(func() {
						vm.Spec.AdvancedOptions = &vmopv1alpha1.VirtualMachineAdvancedOptions{
							DefaultVolumeProvisioningOptions: &vmopv1alpha1.VirtualMachineVolumeProvisioningOptions{
								ThinProvisioned: pointer.Bool(false),
							},
						}
					})

					It("Succeeds", func() {
						vcVM, err := createOrUpdateAndGetVcVM(ctx, vm)
						Expect(err).ToNot(HaveOccurred())

						var o mo.VirtualMachine
						Expect(vcVM.Properties(ctx, vcVM.Reference(), nil, &o)).To(Succeed())

						/* vcsim CL deploy has "thick" but that isn't reflected for this disk. */
						_, backing := getVMHomeDisk(ctx, vcVM, o)
						Expect(backing.ThinProvisioned).To(PointTo(BeFalse()))
					})
				})

				XContext("VM has eager zero provisioning", func() {
					BeforeEach(func() {
						vm.Spec.AdvancedOptions = &vmopv1alpha1.VirtualMachineAdvancedOptions{
							DefaultVolumeProvisioningOptions: &vmopv1alpha1.VirtualMachineVolumeProvisioningOptions{
								EagerZeroed: pointer.Bool(true),
							},
						}
					})

					It("Succeeds", func() {
						vcVM, err := createOrUpdateAndGetVcVM(ctx, vm)
						Expect(err).ToNot(HaveOccurred())

						var o mo.VirtualMachine
						Expect(vcVM.Properties(ctx, vcVM.Reference(), nil, &o)).To(Succeed())

						/* vcsim CL deploy has "eagerZeroedThick" but that isn't reflected for this disk. */
						_, backing := getVMHomeDisk(ctx, vcVM, o)
						Expect(backing.EagerlyScrub).To(PointTo(BeTrue()))
					})
				})

				Context("Should resize root disk", func() {
					newSize := resource.MustParse("4242Gi")

					It("Succeeds", func() {
						vm.Spec.PowerState = vmopv1alpha1.VirtualMachinePoweredOff
						vcVM, err := createOrUpdateAndGetVcVM(ctx, vm)
						Expect(err).ToNot(HaveOccurred())

						var o mo.VirtualMachine
						Expect(vcVM.Properties(ctx, vcVM.Reference(), nil, &o)).To(Succeed())
						disk, _ := getVMHomeDisk(ctx, vcVM, o)
						Expect(disk.CapacityInBytes).ToNot(BeEquivalentTo(newSize.Value()))
						// This is almost always 203 but sometimes it isn't for some reason, so fetch it.
						deviceKey := int(disk.Key)

						vm.Spec.Volumes = []vmopv1alpha1.VirtualMachineVolume{
							{
								Name: "this-api-stinks",
								VsphereVolume: &vmopv1alpha1.VsphereVolumeSource{
									Capacity: corev1.ResourceList{
										corev1.ResourceEphemeralStorage: newSize,
									},
									DeviceKey: &deviceKey,
								},
							},
						}

						vm.Spec.PowerState = vmopv1alpha1.VirtualMachinePoweredOn
						Expect(vmProvider.CreateOrUpdateVirtualMachine(ctx, vm)).To(Succeed())

						Expect(vcVM.Properties(ctx, vcVM.Reference(), nil, &o)).To(Succeed())
						disk, _ = getVMHomeDisk(ctx, vcVM, o)
						Expect(disk.CapacityInBytes).To(BeEquivalentTo(newSize.Value()))
					})
				})
			})

			Context("CNS Volumes", func() {
				cnsVolumeName := "cns-volume-1"

				It("CSI Volumes workflow", func() {
					vm.Spec.PowerState = vmopv1alpha1.VirtualMachinePoweredOff
					_, err := createOrUpdateAndGetVcVM(ctx, vm)
					Expect(err).ToNot(HaveOccurred())

					vm.Spec.PowerState = vmopv1alpha1.VirtualMachinePoweredOn
					By("Add CNS volume to VM", func() {
						vm.Spec.Volumes = []vmopv1alpha1.VirtualMachineVolume{
							{
								Name: cnsVolumeName,
								PersistentVolumeClaim: &vmopv1alpha1.PersistentVolumeClaimVolumeSource{
									PersistentVolumeClaimVolumeSource: corev1.PersistentVolumeClaimVolumeSource{
										ClaimName: "pvc-volume-1",
									},
								},
							},
						}

						err := vmProvider.CreateOrUpdateVirtualMachine(ctx, vm)
						Expect(err).To(HaveOccurred())
						Expect(err.Error()).To(ContainSubstring(fmt.Sprintf("status update pending for persistent volume: %s on VM", cnsVolumeName)))
						Expect(vm.Status.PowerState).To(Equal(vmopv1alpha1.VirtualMachinePoweredOff))
					})

					By("CNS volume is not attached", func() {
						errMsg := "blah blah blah not attached"

						vm.Status.Volumes = []vmopv1alpha1.VirtualMachineVolumeStatus{
							{
								Name:     cnsVolumeName,
								Attached: false,
								Error:    errMsg,
							},
						}

						err := vmProvider.CreateOrUpdateVirtualMachine(ctx, vm)
						Expect(err).To(HaveOccurred())
						Expect(err.Error()).To(ContainSubstring(fmt.Sprintf("persistent volume: %s not attached to VM", cnsVolumeName)))
						Expect(vm.Status.PowerState).To(Equal(vmopv1alpha1.VirtualMachinePoweredOff))
					})

					By("CNS volume is attached", func() {
						vm.Status.Volumes = []vmopv1alpha1.VirtualMachineVolumeStatus{
							{
								Name:     cnsVolumeName,
								Attached: true,
							},
						}
						Expect(vmProvider.CreateOrUpdateVirtualMachine(ctx, vm)).To(Succeed())
						Expect(vm.Status.PowerState).To(Equal(vmopv1alpha1.VirtualMachinePoweredOn))
					})
				})
			})

			Context("When fault domains is enabled", func() {
				const zoneName = "az-1"

				BeforeEach(func() {
					testConfig.WithFaultDomains = true
					// Explicitly place the VM into one of the zones that the test context will create.
					vm.Labels[topology.KubernetesTopologyZoneLabelKey] = zoneName
				})

				It("Reverse lookups existing VM into correct zone", func() {
					_, err := createOrUpdateAndGetVcVM(ctx, vm)
					Expect(err).ToNot(HaveOccurred())

					Expect(vm.Labels).To(HaveKeyWithValue(topology.KubernetesTopologyZoneLabelKey, zoneName))
					Expect(vm.Status.Zone).To(Equal(zoneName))
					delete(vm.Labels, topology.KubernetesTopologyZoneLabelKey)

					Expect(vmProvider.CreateOrUpdateVirtualMachine(ctx, vm)).To(Succeed())
					Expect(vm.Labels).To(HaveKeyWithValue(topology.KubernetesTopologyZoneLabelKey, zoneName))
					Expect(vm.Status.Zone).To(Equal(zoneName))
				})
			})
		})

		Context("VM SetResourcePolicy", func() {
			var resourcePolicy *vmopv1alpha1.VirtualMachineSetResourcePolicy

			JustBeforeEach(func() {
				resourcePolicyName := "test-policy"
				resourcePolicy = getVirtualMachineSetResourcePolicy(resourcePolicyName, nsInfo.Namespace)
				Expect(vmProvider.CreateOrUpdateVirtualMachineSetResourcePolicy(ctx, resourcePolicy)).To(Succeed())
				Expect(ctx.Client.Create(ctx, resourcePolicy)).To(Succeed())

				vm.Annotations["vsphere-cluster-module-group"] = resourcePolicy.Spec.ClusterModules[0].GroupName
				vm.Spec.ResourcePolicyName = resourcePolicy.Name
			})

			AfterEach(func() {
				resourcePolicy = nil
			})

			It("Cluster Modules", func() {
				vcVM, err := createOrUpdateAndGetVcVM(ctx, vm)
				Expect(err).ToNot(HaveOccurred())

				members, err := cluster.NewManager(ctx.RestClient).ListModuleMembers(ctx, resourcePolicy.Status.ClusterModules[0].ModuleUuid)
				Expect(err).ToNot(HaveOccurred())
				Expect(members).To(ContainElements(vcVM.Reference()))
			})

			It("Returns error with non-existence cluster module", func() {
				vm.Annotations["vsphere-cluster-module-group"] = "bogusClusterMod"
				err := vmProvider.CreateOrUpdateVirtualMachine(ctx, vm)
				Expect(err).To(MatchError("ClusterModule bogusClusterMod not found"))
			})
		})

		Context("Delete VM", func() {
			JustBeforeEach(func() {
				Expect(vmProvider.CreateOrUpdateVirtualMachine(ctx, vm)).To(Succeed())
			})

			Context("when the VM is off", func() {
				BeforeEach(func() {
					vm.Spec.PowerState = vmopv1alpha1.VirtualMachinePoweredOff
				})

				It("deletes the VM", func() {
					Expect(vm.Status.PowerState).To(Equal(vmopv1alpha1.VirtualMachinePoweredOff))

					uniqueID := vm.Status.UniqueID
					Expect(ctx.GetVMFromMoID(uniqueID)).ToNot(BeNil())

					Expect(vmProvider.DeleteVirtualMachine(ctx, vm)).To(Succeed())
					Expect(ctx.GetVMFromMoID(uniqueID)).To(BeNil())
				})
			})

			It("when the VM is on", func() {
				Expect(vm.Status.PowerState).To(Equal(vmopv1alpha1.VirtualMachinePoweredOn))

				uniqueID := vm.Status.UniqueID
				Expect(ctx.GetVMFromMoID(uniqueID)).ToNot(BeNil())

				// This checks that we power off the VM prior to deletion.
				Expect(vmProvider.DeleteVirtualMachine(ctx, vm)).To(Succeed())
				Expect(ctx.GetVMFromMoID(uniqueID)).To(BeNil())
			})

			It("returns NotFound when VM does not exist", func() {
				Expect(vmProvider.DeleteVirtualMachine(ctx, vm)).To(Succeed())
				err := vmProvider.DeleteVirtualMachine(ctx, vm)
				Expect(apierrors.IsNotFound(err)).To(BeTrue())
			})

			Context("When fault domains is enabled", func() {
				const zoneName = "az-1"

				BeforeEach(func() {
					testConfig.WithFaultDomains = true
					// Explicitly place the VM into one of the zones that the test context will create.
					vm.Labels[topology.KubernetesTopologyZoneLabelKey] = zoneName
				})

				It("returns NotFound when VM does not exist", func() {
					_, err := createOrUpdateAndGetVcVM(ctx, vm)
					Expect(err).ToNot(HaveOccurred())

					Expect(vmProvider.DeleteVirtualMachine(ctx, vm)).To(Succeed())

					delete(vm.Labels, topology.KubernetesTopologyZoneLabelKey)
					err = vmProvider.DeleteVirtualMachine(ctx, vm)
					Expect(apierrors.IsNotFound(err)).To(BeTrue())
				})

				It("Reverse lookups existing VM into correct zone", func() {
					_, err := createOrUpdateAndGetVcVM(ctx, vm)
					Expect(err).ToNot(HaveOccurred())

					uniqueID := vm.Status.UniqueID
					Expect(ctx.GetVMFromMoID(uniqueID)).ToNot(BeNil())

					Expect(vm.Labels).To(HaveKeyWithValue(topology.KubernetesTopologyZoneLabelKey, zoneName))
					delete(vm.Labels, topology.KubernetesTopologyZoneLabelKey)

					Expect(vmProvider.DeleteVirtualMachine(ctx, vm)).To(Succeed())
					Expect(ctx.GetVMFromMoID(uniqueID)).To(BeNil())
				})
			})
		})

		Context("Guest Heartbeat", func() {
			JustBeforeEach(func() {
				Expect(vmProvider.CreateOrUpdateVirtualMachine(ctx, vm)).To(Succeed())
			})

			It("return guest heartbeat", func() {
				heartbeat, err := vmProvider.GetVirtualMachineGuestHeartbeat(ctx, vm)
				Expect(err).ToNot(HaveOccurred())
				// Just testing for property query: field not set in vcsim.
				Expect(heartbeat).To(BeEmpty())
			})
		})

		Context("Web console ticket", func() {
			JustBeforeEach(func() {
				Expect(vmProvider.CreateOrUpdateVirtualMachine(ctx, vm)).To(Succeed())
			})

			It("return ticket", func() {
				// vcsim doesn't implement this yet so expect an error.
				_, err := vmProvider.GetVirtualMachineWebMKSTicket(ctx, vm, "foo")
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring("does not implement: AcquireTicket"))
			})
		})

		Context("ResVMToVirtualMachineImage", func() {
			JustBeforeEach(func() {
				Expect(vmProvider.CreateOrUpdateVirtualMachine(ctx, vm)).To(Succeed())
			})

			// ResVMToVirtualMachineImage isn't actually used.
			It("returns a VirtualMachineImage", func() {
				vcVM := ctx.GetVMFromMoID(vm.Status.UniqueID)
				Expect(vcVM).ToNot(BeNil())

				// TODO: Need to convert this VM to a vApp (and back).
				// annotations := map[string]string{}
				// annotations[versionKey] = versionVal

				image, err := vsphere.ResVMToVirtualMachineImage(ctx, vcVM)
				Expect(err).ToNot(HaveOccurred())
				Expect(image).ToNot(BeNil())
				Expect(image.Name).ToNot(BeEmpty())
				Expect(image.Name).Should(Equal(vcVM.Name()))
				// Expect(image.Annotations).ToNot(BeEmpty())
				// Expect(image.Annotations).To(HaveKeyWithValue(versionKey, versionVal))
			})
		})
	})
}

// getVMHomeDisk gets the VM's "home" disk. It makes some assumptions about the backing and disk name.
func getVMHomeDisk(
	ctx *builder.TestContextForVCSim,
	vcVM *object.VirtualMachine,
	o mo.VirtualMachine) (*types.VirtualDisk, *types.VirtualDiskFlatVer2BackingInfo) {

	ExpectWithOffset(1, vcVM.Name()).ToNot(BeEmpty())
	ExpectWithOffset(1, o.Datastore).ToNot(BeEmpty())
	var dso mo.Datastore
	ExpectWithOffset(1, vcVM.Properties(ctx, o.Datastore[0], nil, &dso)).To(Succeed())

	devList := object.VirtualDeviceList(o.Config.Hardware.Device)
	l := devList.SelectByBackingInfo(&types.VirtualDiskFlatVer2BackingInfo{
		VirtualDeviceFileBackingInfo: types.VirtualDeviceFileBackingInfo{
			FileName: fmt.Sprintf("[%s] %s/disk-0.vmdk", dso.Name, vcVM.Name()),
		},
	})
	ExpectWithOffset(1, l).To(HaveLen(1))

	disk := l[0].(*types.VirtualDisk)
	backing := disk.Backing.(*types.VirtualDiskFlatVer2BackingInfo)

	return disk, backing
}

func getDVPG(
	ctx *builder.TestContextForVCSim,
	path string) (object.NetworkReference, *object.DistributedVirtualPortgroup) {

	network, err := ctx.Finder.Network(ctx, path)
	ExpectWithOffset(1, err).ToNot(HaveOccurred())
	dvpg, ok := network.(*object.DistributedVirtualPortgroup)
	ExpectWithOffset(1, ok).To(BeTrue())

	return network, dvpg
}