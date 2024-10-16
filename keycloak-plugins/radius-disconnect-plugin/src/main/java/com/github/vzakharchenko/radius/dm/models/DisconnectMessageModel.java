package com.github.vzakharchenko.radius.dm.models;

import jakarta.persistence.Access;
import jakarta.persistence.AccessType;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import jakarta.persistence.Version;
import java.util.Date;

@Entity
@Table(name = "RADIUS_DM_SESSION")
public class DisconnectMessageModel {

    @Id
    @Column(name = "SESSION_ID", length = 128)
    @Access(AccessType.PROPERTY)
    private String id;

    @Column(name = "RADIUS_SESSION_ID")
    private String radiusSessionId;

    @Column(name = "CLIENT_ID")
    private String clientId;

    @Column(name = "USER_ID")
    private String userId;

    @Column(name = "REALM_ID")
    private String realmId;

    @Column(name = "REMOTE_ADDRESS")
    private String address;

    @Column(name = "SECRET")
    private String secret;

    @Column(name = "USER_NAME")
    private String userName;

    @Column(name = "NAS_PORT")
    private String nasPort;

    @Column(name = "NAS_PORT_TYPE")
    private String nasPortType;

    @Column(name = "NAS_IP_ADDRESS")
    private String nasIp;

    @Column(name = "FRAMED_IP_ADDRESS")
    private String framedIp;

    @Column(name = "CALLING_STATION_ID")
    private String callingStationId;

    @Column(name = "CALLED_STATION_ID")
    private String calledStationId;

    @Column(name = "KEYCLOAK_SESSION_ID")
    private String keycloakSessionId;

    @Column(name = "CREATED_DATE")
    private Date createdDate;

    @Column(name = "MODIFY_DATE")
    @Version
    private Date modifyDate;

    public Date getModifyDate() {
        return modifyDate == null ? null : (Date) modifyDate.clone();
    }

    public void setModifyDate(Date modifyDate) {
        this.modifyDate = modifyDate == null ? null : (Date) modifyDate.clone();
    }

    public String getClientId() {
        return clientId;
    }

    public void setClientId(String clientId) {
        this.clientId = clientId;
    }

    public String getUserId() {
        return userId;
    }

    public void setUserId(String userId) {
        this.userId = userId;
    }

    public String getRealmId() {
        return realmId;
    }

    public void setRealmId(String realmId) {
        this.realmId = realmId;
    }

    public String getAddress() {
        return address;
    }

    public void setAddress(String address) {
        this.address = address;
    }

    public String getUserName() {
        return userName;
    }

    public void setUserName(String userName) {
        this.userName = userName;
    }

    public String getNasPort() {
        return nasPort;
    }

    public void setNasPort(String nasPort) {
        this.nasPort = nasPort;
    }

    public String getNasPortType() {
        return nasPortType;
    }

    public void setNasPortType(String nasPortType) {
        this.nasPortType = nasPortType;
    }

    public String getNasIp() {
        return nasIp;
    }

    public void setNasIp(String nasIp) {
        this.nasIp = nasIp;
    }

    public String getFramedIp() {
        return framedIp;
    }

    public void setFramedIp(String framedIp) {
        this.framedIp = framedIp;
    }

    public String getCallingStationId() {
        return callingStationId;
    }

    public void setCallingStationId(String callingStationId) {
        this.callingStationId = callingStationId;
    }

    public Date getCreatedDate() {
        return createdDate == null ? null : (Date) createdDate.clone();
    }

    public void setCreatedDate(Date createdDate) {
        this.createdDate = createdDate == null ? null : (Date) createdDate.clone();
    }


    public String getKeycloakSessionId() {
        return keycloakSessionId;
    }

    public void setKeycloakSessionId(String keycloakSessionId) {
        this.keycloakSessionId = keycloakSessionId;
    }

    public String getSecret() {
        return secret;
    }

    public void setSecret(String secret) {
        this.secret = secret;
    }

    public String getRadiusSessionId() {
        return radiusSessionId;
    }

    public void setRadiusSessionId(String radiusSessionId) {
        this.radiusSessionId = radiusSessionId;
    }

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public String getCalledStationId() {
        return calledStationId;
    }

    public void setCalledStationId(String calledStationId) {
        this.calledStationId = calledStationId;
    }
}
