;;; -*- Mode: LISP; Syntax: Joshua; Package: aplan ; readtable: joshua -*-

;;; Forward chaining rules for filling in information

(in-package :aplan)


;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;
;;; Input Relationships
;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;


;;; Workload is an input to the scheduler
(defrule scheduler-input-workload (:forward)
  ;; assumption is that we know the scheduler
  if [and [object-type-of ?scheduler scheduler]
	  [value-of (?scheduler host-os) ?os-instance]
          [object-type-of ?os-instance operating-system]
          [value-of (?os-instance workload) ?workload]
          [object-type-of ?workload os-workload]]
  then [input-of ?scheduler ?workload]
  )

;;; Scheduler Policy File is an input to the Scheduler
(defrule scheduler-input (:forward)
  ;; assumption is that scheduler is known
  if [and [object-type-of ?scheduler scheduler]
	  [value-of (?scheduler host-os) ?os-instance]
          [object-type-of ?os-instance operating-system]
	  [part-of ?computer ?os-instance]
          [object-type-of ?computer computer]
          [value-of (?computer resources) ?scheduler-policy-file]
          [object-type-of ?scheduler-policy-file scheduler-policy-file]]
  then [input-of ?scheduler ?scheduler-policy-file]
  )

(defrule access-controller-input-password-file (:forward)
  ;; assumption is that logon-controller is known
  if [and [object-type-of ?access-controller access-controller]
	  [value-of (?access-controller host-os) ?os-instance]
          [object-type-of ?os-instance operating-system]
	  [named-part-of ?os-instance access-controller ?access-controller]
          [named-part-of ?computer os ?os-instance]
          [object-type-of ?computer computer]
          [value-of (?computer resources) ?password-file]
          [object-type-of ?password-file password-file]
          ]
  then [input-of ?access-controller ?password-file]
  )

(defrule user-job-admitter-inputs (:forward)
  ;; assumption is that user-job-admitter is knownn
  if [and [object-type-of ?user-job-admitter job-launcher]
	  [value-of (?user-job-admitter host-os) ?os-instance]
          [object-type-of ?os-instance operating-system]
	  ;;check that it's actually the user job admitter
	  [named-part-of (?os-instance job-admitter) user-job-admitter ?user-job-admitter]
	  [value-of (?os-instance job-launch-queue) ?job-launch-queue]
          [object-type-of ?job-launch-queue os-job-launch-request-queue]
	  [named-part-of ?job-launch-queue user-job-launch-request-queue ?user-job-launch-request-queue]
          [object-type-of ?user-job-launch-request-queue job-launch-request-queue]
          ]
  then  [input-of ?user-job-admitter ?user-job-launch-request-queue]
  )

(defrule server-job-admitter-inputs (:forward)
  ;; assumption is that server-job-admitter is knownn
  if [and [object-type-of ?server-job-admitter job-launcher]
	  [value-of (?server-job-admitter host-os) ?os-instance]
          [object-type-of ?os-instance operating-system]
	  ;; check that it's actually the server admitter
          [named-part-of (?os-instance job-admitter) server-job-admitter ?server-job-admitter]
          [value-of (?os-instance job-launch-queue) ?job-launch-queue]
	  [object-type-of ?job-launch-queue os-job-launch-request-queue]
	  [named-part-of ?job-launch-queue server-job-launch-request-queue ?server-job-launch-request-queue]
          [object-type-of ?server-job-launch-request-queue job-launch-request-queue]
          ]
  then  [input-of ?server-job-admitter ?server-job-launch-request-queue]
  )

(defrule logon-controller-inputs (:forward)
  if [and [object-type-of ?logon-controller logon-controller]
	  [value-of (?logon-controller host-os) ?os-instance]
	  [object-type-of ?os-instance operating-system]
          [named-part-of ?os-instance logon-controller ?logon-controller]
          [named-part-of ?computer os ?os-instance]
          [object-type-of ?computer computer]
          [value-of (?computer resources) ?password-file]
          [object-type-of ?password-file password-file]
          ]
  then [input-of ?logon-controller ?password-file]
  ) 

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;
;;; Impact releationships between scheduler and its inputs
;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

;;; NOTE: if the OS object kept track of processes on it (which it doesn't)
;;; then we could do these rules more directly

(defrule impact-trasitivity (:forward)
  if [and [impacts ?intermediate-property ?intermediate-component  ?victim-property ?victim-component]
	  [impacts ?distant-property ?distant-component ?intermediate-property ?intermediate-component]]
  then [impacts ?distant-property ?distant-component ?victim-property ?victim-component]
  )




;;; the fairness of the scheduler controls reliable performance
(defrule scheduler-process-controls-data-set-performance (:forward)
  if [and [object-type-of ?os-instance operating-system]
          [named-part-of ?os-instance scheduler ?scheduler]
          [object-type-of ?scheduler scheduler]
	  [value-of (?os-instance processes) ?process]
	  [object-type-of ?process process]
          ]
  then [impacts fairness ?scheduler performance ?process]
  )

(defrule scheduler-fairness-affects-performance (:forward)
    IF [and [object-type-of ?victim-process process]
	    [value-of (?victim-process host-os) ?victim-os]
	    [object-type-of ?victim-os operating-system]
	    [named-part-of ?victim-os scheduler ?victim-scheduler]
	    [object-type-of ?victim-scheduler scheduler]]
    Then [impacts fairness ?victim-scheduler performance ?victim-process]
    )

;;; The size of a workload affects the workset size of a scheduler
(defrule scheduler-process-controls-data-set-performance-2 (:forward)
  if [and [object-type-of ?os-instance operating-system]
          [named-part-of ?os-instance scheduler ?scheduler]
	  ;; actually the workset is an input not a part
	  ;; but also it's not referenced below
	  ;; [named-part-of ?scheduler workset ?workset]
          [object-type-of ?scheduler scheduler]
	  [value-of (?os-instance processes) ?process]
	  [object-type-of ?process process]
          ]
  then [impacts workset-size ?scheduler performance ?process]
  )

(defrule size-of-workset-impacts-scheduler-workload-size (:forward)
  if [and [object-type-of ?os-instance operating-system]
	  [named-part-of ?os-instance scheduler ?scheduler]
	  [object-type-of ?scheduler scheduler]
	  [input-of ?scheduler ?workload]
	  [object-type-of ?workload os-workload]
	  ]
  then [impacts size ?workload workset-size ?scheduler]
  )

(defrule size-of-part-of-workset-impacts-size-of-full-worset (:forward)
  if [and [object-type-of ?os-instance operating-system]
	  [value-of (?os-instance workload) ?full-workset]
	  [object-type-of ?full-workset os-workload]
	  [part-of ?full-workset ?partial-workset]
	  [object-type-of ?partial-workset workload]
	  ]
  then [impacts size ?partial-workset size ?full-workset]
  )


(defrule size-of-request-queue-impacts-workload-size (:forward)
  if [and [object-type-of ?os-instance operating-system]
	  [named-part-of ?os-insance job-admitter ?job-admitter]
	  [object-type-of ?job-admitter os-job-admitter]
	  [part-of ?job-admitter ?sub-job-admitter]
	  [object-type-of ?sub-job-admitter job-launcher]
	  [input-of ?sub-job-admitter ?job-request-queue]
	  [object-type-of ?job-request-queue job-launch-request-queue]
	  [process-controls-data-set ?sub-job-admitter ?workload]
	  [object-type-of ?workload workload]
	  ]
  then [impacts size ?job-request-queue size ?workload]
  )
 
(defrule size-of-part-of-request-queue-impacts-size-of-full-request-queue (:forward)
  if [and [object-type-of ?os-instance operating-system]
	  [value-of (?os-instance job-launch-queue) ?full-request-queue]
	  [object-type-of ?full-request-queue os-job-launch-request-queue]
	  [part-of ?full-request-queue ?partial-request-queue]
	  [object-type-of ?partial-request-queue job-launch-request-queue]
	  ]
  then [impacts size ?partial-request-queue size ?full-request-queue]
  )


;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;
;;; Impact relationships relating to access controller
;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

;;; access controller impacts privacy
(defrule access-controller-controls-privacy (:forward)
  if [and [object-type-of ?os-instance operating-system]
          [named-part-of ?os-instance access-controller ?access-controller]
          [object-type-of  ?access-controller access-controller]
          [named-part-of ?computer os ?os-instance]
	  [object-type-of ?computer computer]
	  [value-of (?computer resources) ?file]
          [object-type-of ?file file]
          ]
  then [impacts policy ?access-controller data-privacy ?file]
  )

;;; access controller impacts integrity
(defrule access-controller-controls-integrity (:forward)
  if [and [object-type-of ?os-instance operating-system]
          [named-part-of ?os-instance access-controller ?access-controller]
          [object-type-of  ?access-controller access-controller]
          [named-part-of ?computer os ?os-instance]
	  [object-type-of ?computer computer]
	  [value-of (?computer resources) ?file]
          [object-type-of ?file file]
          ]
  then [impacts policy ?access-controller data-integrity ?file]
  )



;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;
;;; Control Relationships between Processers and Data Sets
;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;


;;; active user set
(defrule logon-controller-controls-active-user-set (:forward)
  if [and [object-type-of ?os-instance operating-system]
	  [value-of (?os-instance user-set) ?active-user-set]
          [object-type-of ?active-user-set user-set]
          [named-part-of ?os-instance logon-controller ?logon-controller]
          [object-type-of ?logon-controller logon-controller]
          ]
  then [process-controls-data-set ?logon-controller ?active-user-set]
  )

;;; what controls the parts of workload


;;; User job launcher controls the workload
(defrule user-workload-controls (:forward)
  if [and [object-type-of ?os-instance operating-system]
          [value-of (?os-instance workload) ?workload]
          [object-type-of ?workload os-workload]
          [named-part-of ?workload user-workload ?user-workload]
          [object-type-of ?user-workload workload]
          [value-of (?user-workload os) ?os-instance]
	  [named-part-of (?os-instance job-admitter) user-job-admitter ?user-job-admitter]
          [object-type-of ?user-job-admitter job-launcher]
          ]
  then [process-controls-data-set ?user-job-admitter ?user-workload]
  )

;;; Server job launcher controls the workload
(defrule server-workload-controls (:forward)
  if [and [object-type-of ?os-instance operating-system]
          [value-of (?os-instance workload) ?workload]
          [object-type-of ?workload os-workload]
          [named-part-of ?workload server-workload ?server-workload]
          [object-type-of ?server-workload workload]
          [value-of (?server-workload os) ?os-instance]
          [named-part-of (?os-instance job-admitter) server-job-admitter ?server-job-admitter]
          [object-type-of ?server-job-admitter job-launcher]
          ]
  then [process-controls-data-set ?server-job-admitter ?server-workload]
  )



;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;
;;; Network related stuff
;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defrule put-subnet-on-site (:forward)
  if [and [object-type-of ?site site]
          [object-type-of ?subnet subnet]
          (subnet-is-at-site ?subnet ?site)]
  then (tell [value-of (?site subnets) ?subnet]))

(defrule put-computer-on-subnets (:forward)
  if [and [object-type-of ?computer computer]
          [value-of (?computer ip-addresses) ?ip-address]
          [object-type-of ?subnet subnet]
          (ip-address-is-on-subnet ?ip-address ?subnet)]
  then [value-of (?subnet computers) ?computer])

(defrule fill-in-subnet-routers (:forward)
  if [and [object-type-of ?computer router]
          [object-type-of ?subnet subnet]
          [value-of (?computer subnets) ?subnet]]
   then [value-of (?subnet routers) ?computer])

(defrule fill-in-subnet-switch (:forward)
  if [and [object-type-of ?computer switch]
          [object-type-of ?subnet switched-subnet]
          [value-of (?computer subnets) ?subnet]]
   then [value-of (?subnet switch) ?computer])

(defrule fill-in-computer-site (:forward)
  if [and [object-type-of ?subnet subnet]
          [value-of (?subnet computers) ?computer]
          [value-of (?subnet site) ?site]
          [object-type-of ?site site]]
  then [value-of (?computer site) ?site])

(defrule fill-in-machines-superuser (:forward)
  if [and [object-type-of ?machine computer]
          [value-of (?machine os superuser) ?user]
          [object-type-of ?user user]]
  then [value-of (?user machines) ?machine])

(def-symmetric-pointers capabilities-up-down capability ?c1 more-specific capability ?c2 more-general)

(def-symmetric-pointers capability-pool capability ?capability authorization-pool authorization-pool ?pool capabilities)

(def-symmetric-pointers machine-pool operating-system ?os-instance authorization-pool authorization-pool ?pool machines)

(def-symmetric-pointers user-pool user ?user authorization-pool authorization-pool ?pool users)

(def-symmetric-pointers resource-machine computer-resource ?r machines computer ?c resources)

(def-symmetric-pointers file-directory file ?file directories directory ?directory files)

(def-symmetric-pointers subnet-site subnet ?subnet site site ?site subnets)

(def-symmetric-pointers computer-subnets subnet ?subnet computers computer ?computer subnets)

(def-symmetric-pointers source-class class-file ?class-file source-file java-file ?java-file object-file)

(def-symmetric-pointers class-program class-file ?class-file programs program ?program load-files)

(def-symmetric-pointers process-program process ?process program program ?program processes)

(defrule process-belongs-to-machine (:forward)
  if [and [object-type-of ?os operating-system]
	  [object-type-of ?machine computer]
	  [part-of (?machine os) ?os]
	  [part-of ?os ?part]
	  [object-type-of ?part computer-resource]]
  then [value-of (?part machines) ?machine])
	  

;;; All this needs to be redone in a decision theoretic framework!
;;; inferring desirable properties

;;; These talk about OS instances, need to extend to application instances
;;; and to reflect that application instances are controlled by their OS instances
(defrule os-performance (:forward)
  If [object-type-of ?os-instance operating-system]
  then [desirable-property-of ?os-instance performance])

(defrule process-performance (:forward)
  If [object-type-of ?process process]
  then [desirable-property-of ?process performance])

(defrule os-privacy (:forward)
  If [object-type-of ?os-instance operating-system]
  then [desirable-property-of ?os-instance data-privacy])

(defrule data-resource-privacy (:forward)
  if [object-type-of ?resource data-resource]
  then [desirable-property-of ?resource data-privacy])

(defrule os-integrity (:forward)
  if [object-type-of ?os-instance operating-system]
  then [desirable-property-of ?os-instance data-integrity])

(defrule data-resource-integrity (:forward)
  if [object-type-of ?resource data-resource]
  then [desirable-property-of ?resource data-integrity])

(defrule os-execution-integrity (:forward)
  if [object-type-of ?os-instance operating-system]
  then [desirable-property-of ?os-instance execution-integrity])

;;; Presentation integrity means that a user will see what you intend to see
;;; You can affect this by screwing up the data behind this
;;; Or you can affect this by misdirecting the user to the wrong place
;;; Note: This shouldn't be a property of an os-instance, but rather a property 
;;; of a web-site or something like that.

(defrule os-presentation-integrity (:forward)
  if [object-type-of ?os-instance operating-system]
  then [desirable-property-of ?os-instance presentation-integrity])

(defrule servers-run-root-in-windows (:forward)
  if [and [object-type-of ?server-process server-process]
          [value-of (?server-process host-os) ?os-instance]
          [object-type-of ?os-instance windows]
          [value-of (?os-instance superuser) ?superuser]
          [object-type-of ?superuser user]]
  then [runs-with-permissions-of ?server-process ?superuser])

(defrule servers-run-root-in-unix (:forward)
  if [and [object-type-of ?server-process server-process]
	  [value-of (?server-process host-os) ?os-instance]
          [object-type-of ?os-instance unix]
          [value-of (?os-instance superuser) ?superuser]
          [object-type-of ?superuser user]]
  then [runs-with-permissions-of ?server-process ?superuser])


;; this forces the user to "own" every machine at his site
;; by forward reasoning.
(defrule user-can-use-computer (:forward)
  if [and [object-type-of ?user user]
          [value-of (?user location) ?location]
	  [object-type-of ?computer computer]
	  [value-of (?computer site) ?site]
	  [object-type-of ?site site]
	  (location-is-in-net-segment ?site ?location)]
  then [value-of (?user machines) ?computer])

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;
;;; Knowledge about permissions
;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defrule process-instance-has-permision (:forward)
  If [and [object-type-of ?server-process server-process]
          [runs-with-permissions-of ?server-process ?user]
	  [object-type-of ?user user]
          [has-permission ?user ?an-operation ?an-object]
          ]
  then [has-permission ?server-process ?an-operation ?an-object]
  )

(defrule user-has-permission (:forward)
  if [and [object-type-of ?object computer-resource]
          [value-of (?object capability-requirements) ?requirement]
          [object-type-of ?user user]
	  (unify ?operation (first ?requirement))
	  (has-capability ?user (second ?requirement))
	  ]
  then [has-permission ?user ?operation ?object]
  )

(defun has-capability (user capability)
  (let ((his-capabilities (capabilities user)))
    (labels ((check-one (putative-capability)
               (when (eql putative-capability capability)
                 (return-from has-capability (values t)))
               (mapc #'check-one (more-specific putative-capability))))
      (mapc #'check-one his-capabilities))
    nil)) 

(defrule requires-access-right-translation (:forward)
  if [and [object-type-of ?object computer-resource]
          [value-of (?object capability-requirements) ?requirement]
	  (unify ?requirement (list ?operation ?capability))
	  ]
  then [requires-access-right ?object ?operation ?capability]
  )

(defrule thread-process (:forward)
  if [and [object-type-of ?process process]
	  [value-of (?process host-os) ?os]]
  then [value-of (?os processes) ?process]
  )