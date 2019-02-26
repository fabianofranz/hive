/*
Copyright 2019 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package credentials

import (
	"context"

	"github.com/aws/aws-sdk-go/service/sts"
	log "github.com/sirupsen/logrus"

	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/source"

	ccaws "github.com/openshift/cloud-credential-operator/pkg/aws"
	cccontrollerutils "github.com/openshift/cloud-credential-operator/pkg/controller/utils"
	hivev1 "github.com/openshift/hive/pkg/apis/hive/v1alpha1"
	"github.com/openshift/hive/pkg/awsclient"
)

const (
	controllerName     = "awscredentials"
	adminKubeConfigKey = "kubeconfig"
)

var (
	clusterDeploymentRequiredActions = []string{}
)

func Add(mgr manager.Manager) error {
	return AddToManager(mgr, NewReconciler(mgr))
}

func NewReconciler(mgr manager.Manager) reconcile.Reconciler {
	return &ReconcileAWSCredentials{
		Client:           mgr.GetClient(),
		scheme:           mgr.GetScheme(),
		logger:           log.WithField("controller", controllerName),
		awsClientBuilder: awsclient.NewClient,
	}
}

func AddToManager(mgr manager.Manager, r reconcile.Reconciler) error {
	c, err := controller.New("awscredentials-controller", mgr, controller.Options{Reconciler: r})
	if err != nil {
		return err
	}

	// Watch for changes to ClusterDeployment
	err = c.Watch(&source.Kind{Type: &hivev1.ClusterDeployment{}}, &handler.EnqueueRequestForObject{})
	if err != nil {
		return err
	}

	return nil
}

var _ reconcile.Reconciler = &ReconcileAWSCredentials{}

// ReconcileRemoteMachineSet reconciles the MachineSets generated from a ClusterDeployment object
type ReconcileAWSCredentials struct {
	client.Client
	scheme *runtime.Scheme

	logger log.FieldLogger

	// awsClientBuilder is a function pointer to the function that builds the aws client
	awsClientBuilder func(kClient client.Client, secretName, namespace, region string) (awsclient.Client, error)
}

// Reconcile reads that state of the cluster for a ClusterDeployment object and makes changes to the
// remote cluster MachineSets based on the state read and the worker machines defined in
// ClusterDeployment.Spec.Config.Machines
func (r *ReconcileAWSCredentials) Reconcile(request reconcile.Request) (reconcile.Result, error) {
	// Fetch the ClusterDeployment instance
	cd := &hivev1.ClusterDeployment{}
	err := r.Get(context.TODO(), request.NamespacedName, cd)
	if err != nil {
		if errors.IsNotFound(err) {
			// Object not found, return
			return reconcile.Result{}, nil
		}
		// Error reading the object - requeue the request
		log.WithError(err).Error("error looking up cluster deployment")
		return reconcile.Result{}, err
	}

	cdLog := r.logger.WithFields(log.Fields{
		"clusterDeployment": cd.Name,
		"namespace":         cd.Namespace,
	})

	// just test the AWS credentials
	if cd.Spec.Platform.AWS != nil {
		awsClient, err := r.getAWSClient(cd)
		if err != nil {
			return reconcile.Result{}, err
		}

		cdLog.Info("TESTING AWS CREDENTIALS...")

		err = checkAWSCredentials(awsClient)
		if err != nil {
			return reconcile.Result{}, err
		}

		// TODO: worked, so set a condition on cluster deployment

		log.Info("CHECKING AWS CREDENTIALS PERMISSIONS...")

		// check if the AWS credentials have the required roles
		ccAWSClient, err := r.getCloudCredentialAWSClient(cd)
		if err != nil {
			return reconcile.Result{}, err
		}

		allowed, err := cccontrollerutils.CheckPermissionsAgainstActions(ccAWSClient, clusterDeploymentRequiredActions, cdLog)
		if err != nil {
			return reconcile.Result{}, err
		}

		// NOT allowed to perform the actions we'll need
		if !allowed {

		}
	}

	return reconcile.Result{}, nil

}

// getAWSClient generates an awsclient
func (r *ReconcileAWSCredentials) getAWSClient(cd *hivev1.ClusterDeployment) (awsclient.Client, error) {
	// This allows for using host profiles for AWS auth.
	var secretName, regionName string

	if cd != nil && cd.Spec.AWS != nil && cd.Spec.PlatformSecrets.AWS != nil {
		secretName = cd.Spec.PlatformSecrets.AWS.Credentials.Name
		regionName = cd.Spec.AWS.Region
	}

	awsClient, err := r.awsClientBuilder(r.Client, secretName, cd.Namespace, regionName)
	if err != nil {
		return nil, err
	}

	return awsClient, nil
}

func (r *ReconcileAWSCredentials) getCloudCredentialAWSClient(cd *hivev1.ClusterDeployment) (ccaws.Client, error) {
	var secretName string

	if cd != nil && cd.Spec.AWS != nil && cd.Spec.PlatformSecrets.AWS != nil {
		secretName = cd.Spec.PlatformSecrets.AWS.Credentials.Name
	}

	accessKeyID, secretAccessKey, err := ccaws.LoadCredsFromSecret(r.Client, cd.Namespace, secretName)
	if err != nil {
		return nil, err
	}

	ccAWSClient, err := ccaws.NewClient(accessKeyID, secretAccessKey)
	if err != nil {
		return nil, err
	}

	return ccAWSClient, nil
}

func checkAWSCredentials(client awsclient.Client) error {
	req := &sts.GetCallerIdentityInput{}
	_, err := client.GetCallerIdentity(req)
	return err
}
