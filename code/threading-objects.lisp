;;; -*- Mode: LISP; Syntax: Joshua; Package: aplan ; readtable: joshua -*-

;;; Forward chaining rules for filling in information

(in-package :aplan)


(defrule cycle-pool-to-machine (:forward)
  if [and [ltms:object-type-of ?machine computer]
	  [ltms:named-part-of ?machine cycle-pool ?cycle-pool]
	  [ltms:object-type-of ?cycle-pool cycle-pool]]
  then [ltms:value-of (?cycle-pool machines) ?machine]
  )

(defrule cycle-pool-to-os (:forward)
  if [and [ltms:object-type-of ?cycle-pool cycle-pool]
	  [ltms:value-of (?cycle-pool machines) ?machine]
	  [ltms:object-type-of ?machine computer]
	  [ltms:named-part-of ?machine os ?os]
	  ]
  then [ltms:value-of (?cycle-pool os) ?os]
  )

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;
;;; Input Relationships
;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;


;;; Workload is an input to the scheduler
(defrule scheduler-input-workload (:forward)
  ;; assumption is that we know the scheduler
  if [and [ltms:object-type-of ?scheduler scheduler]
	  [ltms:value-of (?scheduler host-os) ?os-instance]
          [ltms:object-type-of ?os-instance operating-system]
          [ltms:value-of (?os-instance workload) ?workload]
          [ltms:object-type-of ?workload os-workload]]
  then [input-of ?scheduler ?workload]
  )

;;; Scheduler Policy File is an input to the Scheduler
(defrule scheduler-input (:forward)
  ;; assumption is that scheduler is known
  if [and [ltms:object-type-of ?scheduler scheduler]
	  [ltms:value-of (?scheduler host-os) ?os-instance]
          [ltms:object-type-of ?os-instance operating-system]
	  [part-of ?computer ?os-instance]
          [ltms:object-type-of ?computer computer]
          [ltms:value-of (?computer resources) ?scheduler-policy-file]
          [ltms:object-type-of ?scheduler-policy-file scheduler-policy-file]]
  then [input-of ?scheduler ?scheduler-policy-file]
  )

(defrule access-controller-input-password-file (:forward)
  ;; assumption is that logon-controller is known
  if [and [ltms:object-type-of ?access-controller access-controller]
	  [ltms:value-of (?access-controller host-os) ?os-instance]
          [ltms:object-type-of ?os-instance operating-system]
	  [named-part-of ?os-instance access-controller ?access-controller]
          [named-part-of ?computer os ?os-instance]
          [ltms:object-type-of ?computer computer]
          [ltms:value-of (?computer resources) ?password-file]
          [ltms:object-type-of ?password-file password-file]
          ]
  then [input-of ?access-controller ?password-file]
  )

(defrule user-job-admitter-inputs (:forward)
  ;; assumption is that user-job-admitter is knownn
  if [and [ltms:object-type-of ?user-job-admitter job-launcher]
	  [ltms:value-of (?user-job-admitter host-os) ?os-instance]
          [ltms:object-type-of ?os-instance operating-system]
	  ;;check that it's actually the user job admitter
	  [named-part-of (?os-instance job-admitter) user-job-admitter ?user-job-admitter]
	  [ltms:value-of (?os-instance job-launch-queue) ?job-launch-queue]
          [ltms:object-type-of ?job-launch-queue os-job-launch-request-queue]
	  [named-part-of ?job-launch-queue user-job-launch-request-queue ?user-job-launch-request-queue]
          [ltms:object-type-of ?user-job-launch-request-queue job-launch-request-queue]
          ]
  then  [input-of ?user-job-admitter ?user-job-launch-request-queue]
  )

(defrule server-job-admitter-inputs (:forward)
  ;; assumption is that server-job-admitter is knownn
  if [and [ltms:object-type-of ?server-job-admitter job-launcher]
	  [ltms:value-of (?server-job-admitter host-os) ?os-instance]
          [ltms:object-type-of ?os-instance operating-system]
	  ;; check that it's actually the server admitter
          [named-part-of (?os-instance job-admitter) server-job-admitter ?server-job-admitter]
          [ltms:value-of (?os-instance job-launch-queue) ?job-launch-queue]
	  [ltms:object-type-of ?job-launch-queue os-job-launch-request-queue]
	  [named-part-of ?job-launch-queue server-job-launch-request-queue ?server-job-launch-request-queue]
          [ltms:object-type-of ?server-job-launch-request-queue job-launch-request-queue]
          ]
  then  [input-of ?server-job-admitter ?server-job-launch-request-queue]
  )

(defrule logon-controller-inputs (:forward)
  if [and [ltms:object-type-of ?logon-controller logon-controller]
	  [ltms:value-of (?logon-controller host-os) ?os-instance]
	  [ltms:object-type-of ?os-instance operating-system]
          [named-part-of ?os-instance logon-controller ?logon-controller]
          [named-part-of ?computer os ?os-instance]
          [ltms:object-type-of ?computer computer]
          [ltms:value-of (?computer resources) ?password-file]
          [ltms:object-type-of ?password-file password-file]
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
  if [and [ltms:object-type-of ?os-instance operating-system]
          [named-part-of ?os-instance scheduler ?scheduler]
          [ltms:object-type-of ?scheduler scheduler]
	  [ltms:value-of (?os-instance processes) ?process]
	  [ltms:object-type-of ?process process]
          ]
  then [impacts fairness ?scheduler performance ?process]
  )

(defrule scheduler-fairness-affects-performance (:forward)
    IF [and [ltms:object-type-of ?victim-process process]
	    [ltms:value-of (?victim-process host-os) ?victim-os]
	    [ltms:object-type-of ?victim-os operating-system]
	    [named-part-of ?victim-os scheduler ?victim-scheduler]
	    [ltms:object-type-of ?victim-scheduler scheduler]]
    Then [impacts fairness ?victim-scheduler performance ?victim-process]
    )

;;; The size of a workload affects the workset size of a scheduler
(defrule scheduler-process-controls-data-set-performance-2 (:forward)
  if [and [ltms:object-type-of ?os-instance operating-system]
          [named-part-of ?os-instance scheduler ?scheduler]
	  ;; actually the workset is an input not a part
	  ;; but also it's not referenced below
	  ;; [named-part-of ?scheduler workset ?workset]
          [ltms:object-type-of ?scheduler scheduler]
	  [ltms:value-of (?os-instance processes) ?process]
	  [ltms:object-type-of ?process process]
          ]
  then [impacts workset-size ?scheduler performance ?process]
  )

(defrule size-of-workset-impacts-scheduler-workload-size (:forward)
  if [and [ltms:object-type-of ?os-instance operating-system]
	  [named-part-of ?os-instance scheduler ?scheduler]
	  [ltms:object-type-of ?scheduler scheduler]
	  [input-of ?scheduler ?workload]
	  [ltms:object-type-of ?workload os-workload]
	  ]
  then [impacts size ?workload workset-size ?scheduler]
  )

(defrule size-of-part-of-workset-impacts-size-of-full-worset (:forward)
  if [and [ltms:object-type-of ?os-instance operating-system]
	  [ltms:value-of (?os-instance workload) ?full-workset]
	  [ltms:object-type-of ?full-workset os-workload]
	  [part-of ?full-workset ?partial-workset]
	  [ltms:object-type-of ?partial-workset workload]
	  ]
  then [impacts size ?partial-workset size ?full-workset]
  )


(defrule size-of-request-queue-impacts-workload-size (:forward)
  if [and [ltms:object-type-of ?os-instance operating-system]
	  [named-part-of ?os-insance job-admitter ?job-admitter]
	  [ltms:object-type-of ?job-admitter os-job-admitter]
	  [part-of ?job-admitter ?sub-job-admitter]
	  [ltms:object-type-of ?sub-job-admitter job-launcher]
	  [input-of ?sub-job-admitter ?job-request-queue]
	  [ltms:object-type-of ?job-request-queue job-launch-request-queue]
	  [process-controls-data-set ?sub-job-admitter ?workload]
	  [ltms:object-type-of ?workload workload]
	  ]
  then [impacts size ?job-request-queue size ?workload]
  )
 
(defrule size-of-part-of-request-queue-impacts-size-of-full-request-queue (:forward)
  if [and [ltms:object-type-of ?os-instance operating-system]
	  [ltms:value-of (?os-instance job-launch-queue) ?full-request-queue]
	  [ltms:object-type-of ?full-request-queue os-job-launch-request-queue]
	  [part-of ?full-request-queue ?partial-request-queue]
	  [ltms:object-type-of ?partial-request-queue job-launch-request-queue]
	  ]
  then [impacts size ?partial-request-queue size ?full-request-queue]
  )

(defrule performance-affects-control-system-timeliness (:forward)
  if [ltms:object-type-of ?process control-system-process]
  then [impacts performance ?process timeliness ?process]
  )

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;
;;; Impact relationships relating to access controller
;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

;;; access controller impacts privacy
(defrule access-controller-controls-privacy (:forward)
  if [and [ltms:object-type-of ?os-instance operating-system]
          [named-part-of ?os-instance access-controller ?access-controller]
          [ltms:object-type-of  ?access-controller access-controller]
          [named-part-of ?computer os ?os-instance]
	  [ltms:object-type-of ?computer computer]
	  [ltms:value-of (?computer resources) ?file]
          [ltms:object-type-of ?file file]
          ]
  then [impacts policy ?access-controller data-privacy ?file]
  )

;;; access controller impacts integrity
(defrule access-controller-controls-integrity (:forward)
  if [and [ltms:object-type-of ?os-instance operating-system]
          [named-part-of ?os-instance access-controller ?access-controller]
          [ltms:object-type-of  ?access-controller access-controller]
          [named-part-of ?computer os ?os-instance]
	  [ltms:object-type-of ?computer computer]
	  [ltms:value-of (?computer resources) ?file]
          [ltms:object-type-of ?file file]
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
  if [and [ltms:object-type-of ?os-instance operating-system]
	  [ltms:value-of (?os-instance user-set) ?active-user-set]
          [ltms:object-type-of ?active-user-set user-set]
          [named-part-of ?os-instance logon-controller ?logon-controller]
          [ltms:object-type-of ?logon-controller logon-controller]
          ]
  then [process-controls-data-set ?logon-controller ?active-user-set]
  )

;;; what controls the parts of workload


;;; User job launcher controls the workload
(defrule user-workload-controls (:forward)
  if [and [ltms:object-type-of ?os-instance operating-system]
          [ltms:value-of (?os-instance workload) ?workload]
          [ltms:object-type-of ?workload os-workload]
          [named-part-of ?workload user-workload ?user-workload]
          [ltms:object-type-of ?user-workload workload]
          [ltms:value-of (?user-workload os) ?os-instance]
	  [named-part-of (?os-instance job-admitter) user-job-admitter ?user-job-admitter]
          [ltms:object-type-of ?user-job-admitter job-launcher]
          ]
  then [process-controls-data-set ?user-job-admitter ?user-workload]
  )

;;; Server job launcher controls the workload
(defrule server-workload-controls (:forward)
  if [and [ltms:object-type-of ?os-instance operating-system]
          [ltms:value-of (?os-instance workload) ?workload]
          [ltms:object-type-of ?workload os-workload]
          [named-part-of ?workload server-workload ?server-workload]
          [ltms:object-type-of ?server-workload workload]
          [ltms:value-of (?server-workload os) ?os-instance]
          [named-part-of (?os-instance job-admitter) server-job-admitter ?server-job-admitter]
          [ltms:object-type-of ?server-job-admitter job-launcher]
          ]
  then [process-controls-data-set ?server-job-admitter ?server-workload]
  )



;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;
;;; Network related stuff
;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defrule put-subnet-on-site (:forward)
  if [and [ltms:object-type-of ?site site]
          [ltms:object-type-of ?subnet subnet]
          (subnet-is-at-site ?subnet ?site)]
  then (tell [ltms:value-of (?site subnets) ?subnet]))

(defrule put-computer-on-subnets (:forward)
  if [and [ltms:object-type-of ?computer computer]
          [ltms:value-of (?computer ip-addresses) ?ip-address]
          [ltms:object-type-of ?subnet subnet]
          (ip-address-is-on-subnet ?ip-address ?subnet)]
  then [ltms:value-of (?subnet computers) ?computer])

(defrule fill-in-subnet-routers (:forward)
  if [and [ltms:object-type-of ?computer router]
          [ltms:object-type-of ?subnet subnet-mixin]
          [ltms:value-of (?computer subnets) ?subnet]]
   then [ltms:value-of (?subnet routers) ?computer])

(defrule fill-in-subnet-switch (:forward)
  if [and [ltms:object-type-of ?computer switch]
          [ltms:object-type-of ?subnet switched-subnet]
          [ltms:value-of (?computer subnets) ?subnet]]
  then [ltms:value-of (?subnet switch) ?computer])

(defrule router-on-switched-network-is-switch (:forward)
  if [and [ltms:object-type-of ?computer router]
          [ltms:object-type-of ?subnet switched-subnet]
          [ltms:value-of (?computer subnets) ?subnet]]
   then [ltms:value-of (?subnet switch) ?computer])

(defrule fill-in-computer-site (:forward)
  if [and [ltms:object-type-of ?subnet subnet]
          [ltms:value-of (?subnet computers) ?computer]
          [ltms:value-of (?subnet site) ?site]
          [ltms:object-type-of ?site site]]
  then [ltms:value-of (?computer site) ?site])

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;
;;; Computers OS etc
;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defrule fill-in-machine-os (:forward)
  if [and [ltms:object-type-of ?machine computer]
	  [ltms:named-part-of ?machine os ?os-instance]
	  ]
  then [ltms:value-of (?os-instance machine) ?machine]
  )

(defrule fill-in-machine-os-users (:forward)
  if [and [ltms:object-type-of ?machine computer]
	  [ltms:named-part-of ?machine os ?os-instance]
	  [ltms:object-type-of ?os-instance operating-system]
	  [ltms:value-of (?machine users) ?user]
	  [ltms:object-type-of ?user user]
	  ]
  then [ltms:value-of (?os-instance users) ?user]
  )


(defrule fill-in-machines-superuser (:forward)
  if [and [ltms:object-type-of ?machine computer]
          [ltms:value-of (?machine os superuser) ?user]
          [ltms:object-type-of ?user user]]
  then [ltms:value-of (?user machines) ?machine])



(def-symmetric-pointers machine-superusers operating-system ?the-os superuser user ?superuser superuser-for)

(def-symmetric-pointers machine-users computer ?the-computer users user ?the-user machines)

(def-symmetric-pointers enterprise-site enterprise ?the-enterprise sites site ?the-site enterprise)

(def-symmetric-pointers ensemble-user ensemble ?the-ensemble typical-user user ?the-user ensemble)

(def-symmetric-pointers ensemble-typical-computer ensemble ?the-ensemble typical-computer computer ?the-computer ensemble
			:to-condition (typical-p t))

(def-symmetric-pointers ensemble-typical-user ensemble ?the-ensemble typical-user user ?the-user ensemble
			:to-condition (typical-p t))

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
  if [and [ltms:object-type-of ?os operating-system]
	  [ltms:object-type-of ?machine computer]
	  [part-of (?machine os) ?os]
	  [part-of ?os ?part]
	  [ltms:object-type-of ?part computer-resource]]
  then [ltms:value-of (?part machines) ?machine])
	  

;;; All this needs to be redone in a decision theoretic framework!
;;; inferring desirable properties

;;; These talk about OS instances, need to extend to application instances
;;; and to reflect that application instances are controlled by their OS instances
(defrule os-performance (:forward)
  If [ltms:object-type-of ?os-instance operating-system]
  then [desirable-property-of ?os-instance performance])

(defrule process-performance (:forward)
  If [ltms:object-type-of ?process process]
  then [desirable-property-of ?process performance])

(defrule os-privacy (:forward)
  If [ltms:object-type-of ?os-instance operating-system]
  then [desirable-property-of ?os-instance data-privacy])

(defrule data-resource-privacy (:forward)
  if [ltms:object-type-of ?resource data-resource]
  then [desirable-property-of ?resource data-privacy])

(defrule os-integrity (:forward)
  if [ltms:object-type-of ?os-instance operating-system]
  then [desirable-property-of ?os-instance data-integrity])

(defrule data-resource-integrity (:forward)
  if [ltms:object-type-of ?resource data-resource]
  then [desirable-property-of ?resource data-integrity])

(defrule os-execution-integrity (:forward)
  if [ltms:object-type-of ?os-instance operating-system]
  then [desirable-property-of ?os-instance execution-integrity])

;;; Presentation integrity means that a user will see what you intend to see
;;; You can affect this by screwing up the data behind this
;;; Or you can affect this by misdirecting the user to the wrong place
;;; Note: This shouldn't be a property of an os-instance, but rather a property 
;;; of a web-site or something like that.

(defrule os-presentation-integrity (:forward)
  if [ltms:object-type-of ?os-instance operating-system]
  then [desirable-property-of ?os-instance presentation-integrity])

;;; Independence means freedom from control by an external source
(defrule os-independence (:forward)
  if [ltms:object-type-of ?os-instance operating-system]
  then [desirable-property-of ?os-instance independence])

;;; control system processes have two desirable properties
;;; accuracy and timeliness

(defrule control-system-accuracy (:forward)
  if [ltms:object-type-of ?process control-system-process]
  then [desirable-property-of ?process accuracy])

(defrule inputs-affect-accuracy-of-control-system-process (:forward)
  if [and [ltms:object-type-of ?process control-system-process]
	  [input-of ?process ?file]
	  [ltms:object-type-of ?file file]]
  then [impacts data-integrity ?file accuracy ?process])

(defrule control-system-timeliness (:forward)
  if [ltms:object-type-of ?process control-system-process]
  then [desirable-property-of ?process timeliness])

(defrule servers-run-root-in-windows (:forward)
  if [and [ltms:object-type-of ?server-process server-process]
          [ltms:value-of (?server-process host-os) ?os-instance]
          [ltms:object-type-of ?os-instance windows]
          [ltms:value-of (?os-instance superuser) ?superuser]
          [ltms:object-type-of ?superuser user]]
  then [runs-with-permissions-of ?server-process ?superuser])

(defrule servers-run-root-in-unix (:forward)
  if [and [ltms:object-type-of ?server-process server-process]
	  [ltms:value-of (?server-process host-os) ?os-instance]
          [ltms:object-type-of ?os-instance unix]
          [ltms:value-of (?os-instance superuser) ?superuser]
          [ltms:object-type-of ?superuser user]]
  then [runs-with-permissions-of ?server-process ?superuser])


;;; this forces the user to "own" every machine at his site
;;; by forward reasoning.  
;;; I'm not sure I want to do this, when we define a user
;;; we can say what his machines are
;;; plus typically we have a typical user and a typical machine
;;; and that gets threaded by thread-user-machines

;;;(defrule user-can-use-computer (:forward)
;;;  if [and [ltms:object-type-of ?user user]
;;;          [ltms:value-of (?user location) ?location]
;;;	  [ltms:object-type-of ?computer computer]
;;;	  [ltms:value-of (?computer site) ?site]
;;;	  [ltms:object-type-of ?site site]
;;;	  (location-is-in-net-segment ?site ?location)]
;;;  then [ltms:value-of (?user machines) ?computer])


;;; Note:
;;; I guess there's a redundant represeentation
;;; Between uses-machine and the machines slot
;;; in the user object:

(defrule uses-machine-to-machines (:forward)
  if [and [uses-machine ?user ?machine]
	  [ltms:object-type-of ?user user]
	  [ltms:object-type-of ?machine computer]]
  then [ltms:value-of (?user machines) ?machine])


;;; This was to thread up the "location" field of users
;;; But that field was really there for the attacker
;;; So this isn't right.
;;;(defrule user-at-location (:forward)
;;;  if [and [ltms:object-type-of ?user user]
;;;	  [ltms:value-of (?user machines) ?machine]
;;;	  [ltms:object-type-of ?machine computer]
;;;	  [ltms:value-of (?machine ip-addresses) ?ip-address]
;;;	  [ltms:object-type-of ?ip-address ip-address]
;;;	  [ltms:object-type-of ?subnet subnet]
;;;	  (ip-address-is-on-subnet ?ip-address ?subnet)]
;;;  then [ltms:value-of (?user location) ?subnet])

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;
;;; Knowledge about permissions
;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defrule process-instance-has-permision (:forward)
  If [and [ltms:object-type-of ?server-process server-process]
          [runs-with-permissions-of ?server-process ?user]
	  [ltms:object-type-of ?user user]
          [has-permission ?user ?an-operation ?an-object]
          ]
  then [has-permission ?server-process ?an-operation ?an-object]
  )

(defrule user-has-permission (:forward)
  if [and [ltms:object-type-of ?object computer-resource]
          [ltms:value-of (?object capability-requirements) ?requirement]
          [ltms:object-type-of ?user user]
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

(defun has-relevant-capability (user right object)
  (ask* `[requires-access-right ,object ,right ?capability]
	(when (has-capability user ?capability)
	  (return-from has-relevant-capability t)))
  nil)

(defrule requires-access-right-translation (:forward)
  if [and [ltms:object-type-of ?object computer-resource]
          [ltms:value-of (?object capability-requirements) ?requirement]
	  (unify ?requirement (list ?operation ?capability))
	  ]
  then [requires-access-right ?object ?operation ?capability]
  )

(defrule thread-process (:forward)
  if [and [ltms:object-type-of ?process process]
	  [ltms:value-of (?process host-os) ?os]]
  then [ltms:value-of (?os processes) ?process]
  )

(defrule thread-process-host-os (:forward)
  if [and [ltms:object-type-of ?process process]
	  [ltms:value-of (?process machines) ?machine]
	  [named-part-of ?machine os ?os-instance]]
  then [ltms:value-of (?process host-os) ?os-instance])

(defrule thread-superuser (:forward)
  if [and [ltms:object-type-of ?machine computer]
	  [named-part-of ?machine os ?os-instance]
	  [ltms:object-type-of ?os-instance operating-system]
	  [ltms:value-of (?os-instance superuser) ?user]
	  [ltms:object-type-of ?user user]]
  then [ltms:value-of (?user machines) ?machine])

;;; Make the typical user of an ensemble
;;; use the typical machine of that ensemble
(defrule thread-user-machines (:forward)
  if [and [ltms:object-type-of ?user user]
	  [ltms:value-of (?user typical-p) t]
	  [ltms:value-of (?user ensemble) ?ensemble]
	  [ltms:object-type-of ?ensemble ensemble]
	  [ltms:value-of (?ensemble typical-computer) ?machine]
	  [ltms:object-type-of ?machine computer]]
  then [ltms:value-of (?user machines) ?machine])

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;
;;; Bus related stuff
;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defrule add-to-connected-systems (:forward)
  if [and [object-type-of ?device hardware]
	  [connected-to ?device ? ?bus ?]
	  [object-type-of ?bus unmastered-medium]]
  then [ltms:value-of (?bus connected-systems) ?device]
  )

(defrule anybody-is-master-on-canbus (:forward)
  if [and [object-type-of ?device hardware]
	  [ltms:value-of (?device hardware-interfaces) ?interface]
	  [object-type-of ?bus unmastered-medium]
	  [connected-to ?computer ?interface ?bus ?slot]]
  then [can-master ?device ?bus]
  )

(defrule master-on-bus-can-slave-others (:forward)
  if [and [object-type-of ?master hardware]
	  [object-type-of ?bus unmastered-medium]
	  [can-master ?master ?bus]
	  [object-type-of ?victim hardware]
	  [connected-to ?victim ?interface ?bus ?slot]
	  (not (eql ?master ?victim))
	  ]
  then [can-be-mastered-by ?master ?victim ?bus]
  )

(defrule anbody-can-issue-command-on-canbus (:forward)
  if [and [object-type-of ?bus unmastered-medium]
	  [object-type-of ?master hardware]
	  [can-be-mastered-by ?master ?victim ?bus]
	  [object-type-of ?victime peripheral]
	  [command-to ?victim ?command]]
  then [can-issue-command-to ?master ?command ?victim ?bus]
  )

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;
;;; Switched Network related stuff
;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;
;;; Web Server Vulnerabilities
;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defrule apache-can-be-hacked-1 (:forward)
  if [object-type-of ?process apache-web-server-process]
  then [vulnerable-to-overflow-attack ?process]
  )
